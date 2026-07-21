# sfs — Konzept & Lösungsstrategie

*Filedata-Graph mit byte-genauer Superseding-Lineage, gebaut für agentic time und viele Rechner. — Stand: 2026-06-23.*

Dieses Dokument ist eine **komplette Lösungsstrategie**. Alle Decision Points (D-0 bis D-23) wurden gemeinsam durchdiskutiert und entschieden; die Begründungen stehen jeweils dabei. Abschnitt 12 ist Addendum A (NoSQL-Surface), Abschnitt 13 Addendum B (WASM-Ausführungsmodell). Aligned zu [Zero-Principle](../../../../../zero_concept/docs/groundwork/manifest/manifest-ai.md); positioniert als **graph-basiertes Tool + Substrat + eigenständiges Produkt** (wegen eigener SaaS-Schicht) zugleich.

> **Reality-Check (Stand 2026-07-20).** Dieses Dokument ist das *Design*; wo Implementierung und Design auseinanderlaufen, gelten die folgenden Fakten (die Details stehen als *Amendment* an den betroffenen Stellen):
> - **Kernel-Treiber ist die primäre FS-Oberfläche.** Das Design nennt den nativen FS-Treiber unter „Offen" (D-23); tatsächlich existiert ein vollständiger In-Kernel-Treiber (`sfs.ko`, ~22.500 Zeilen C, volle VFS-Tabellen inkl. In-Kernel-AEAD/XTS/Ed25519, Page-Cache, xattr/ACL, NFS-Export). Der FUSE-Mount (Abschnitt 8) bleibt der portable Pfad; der performante Pfad ist der Kernel-Treiber.
> - **Format ist v12-only, kein „beliebiger Reader".** Der Zero-Lock-In-/Self-Describing-Anspruch gilt konzeptionell; praktisch liest den Container nur der **exakt passende sfs-Reader** ab `SFS_FORMAT_VERSION` 12 (Clean-Cut: Salt + **ein** Content-Key (D4c) + xattr-Streams (D3) + Argon2id-KDF (D8c)). Ältere Container werden **nicht** migriert.
> - **POSIX-Metadaten sind weiter als im Ursprungsdesign:** persistente Hardlink-Aliase, Nanosekunden-Zeiten, xattrs/ACL und Mount-seitige Write-Bündelung sind implementiert. Noch unvollständig sind vor allem `nlink`-Accounting/Alias-Cache-Invalidierung; dazu bleibt der Katalog pro Datei teuer. Deshalb weiterhin kein General-Purpose-Dateisystem.
> - **Interner `.sfs/`-Namespace:** interne Engine-Keys sind relativ (`.sfs/...`), gemountete Nutzerpfade absolut (`/...`). Dadurch erscheinen die internen Keys weder im FUSE- noch Kernel-Root-Scan; das ist eine Namespace-Invariante, kein nachträglicher FUSE-Filter.

---

## 1. Essenz & Positionierung

> **Terminology note for 1.0.0-rc.1:** This historical design record uses
> “Zero-Knowledge” as shorthand for client-side content encryption. The release
> claim is narrower: the server cannot decrypt content or private paths, but it
> sees account, object, size, timing, access-pattern, and protocol metadata.

**sfs ist ein identity+version-adressierter Filedata-Graph mit byte-genauer Superseding-Lineage, der sich über viele Rechner delta-synct und sich je nach Betrachter als gemountetes Dateisystem, eingebettete Bibliothek oder Graph-API zeigt — mit einem Zero-Knowledge-SaaS als reiner Transport-/Ablage-Schicht dahinter.**

Leitbild: **Datei = Spitze des Eisbergs.** Der Graph ist die Substanz darunter; die Datei ist nur die primäre Surface für OS-Apps. Eine iOS-App, eine Cloud-SaaS-Anwendung oder ein agentic Swarm hat jeweils eine andere Primär-Surface auf dasselbe Substrat.

**Name (D-0, entschieden):** `sfs` ist der Engine-/Format-Name — bewusst in der Reihe **zfs / apfs / sfs**, was es sofort als Filesystem lesbar macht und direkt gegen die positioniert, die es ablösen will. Das „S" bleibt **multivalent**: **S**ynced · **S**ecure · **S**ubstrate · fa**S**t · **S**ourcesave. Familien-Produkt-Slot: **Zero-FS**.

Drei Rollen zugleich:
- **Tool** — Querschnitts-Werkzeug in der Reihe der graph-basierten Zero-Tools.
- **Substrat** — Speicher-/Sync-Ebene, auf der andere Anwendungen ruhen (Session-Storage, Offsite-Sync, In-Memory-Container).
- **Eigenständiges Produkt** — wegen eigener Zero-Knowledge-SaaS und eigenem Auth-Modell.

**Familien-Verhältnis (entschieden, Option A):** sfs **absorbiert die Mechanismen** von Zero-Sync, Zero-Backup und Zero-Share. Diese drei werden zu *Framings/Sichten* auf sfs (Sync = eingebaut; Backup = Lineage + Offsite mit Lineage-Erhalt; Share = verschlüsseltes Fragment-Sharing), statt eigener Implementierungen. Ein Substrat, drei Anwendungs-Sichten — sehr Zero (Services komponieren Tools). Die bestehenden Skizzen in der Zero-Produktkarte werden entsprechend zurückgestuft/umgeschrieben.

**Drei Dedications**, die das Design prägen:
1. **Speed** — der aktuelle Stand einer Datenorganisation (file/blob/record) muss extrem schnell abrufbar sein, Richtung *bare-metal minus optimaler Verschlüsselung*. Historie ist nicht speed-kritisch.
2. **Secure** — beweisbar sicher: das SaaS ist strikt Zero-Knowledge, Krypto ist agil und hardware-optimiert.
3. **Synced** — delta-orientierter Sync über viele OS, mit inhärenter Versionskontrolle ohne separates VCS.

---

## 2. Architektur-Rückgrat (Eisberg-Modell)

Eine Kern-Engine, mehrere Surfaces, ein bewusst „dummes, blindes" Backend.

```
            ┌─ Surface: FS-Mount (FUSE/NFS, "Projektordner als sfs einhängen")
            ├─ Surface: Embedded / in-memory (SaaS-App, Server-Session-Store)
  CORE  ───┼─ Surface: Graph-API / SDK (Agenten nativ: Fragmente, Deltas, Strains)
 ENGINE     └─ Surface: App-nativ (z. B. iOS mit eigener Primär-Surface)
   │
   │  Filedata-Graph: Fragmente (identity+version-adressiert) + Superseding-Kanten
   │  Hot Path:  materialisierter Head (= lebende Chunk-Liste, bare-metal-naher Read)
   │  Cold Path: aufgehobene alte Chunks · Strains (divergierbar) · Commit/Track-Scopes
   │  Krypto-agile Block-Schicht (Cipher pro Container verhandelbar, hardware-optimiert)
   │
   └─ Sync-Engine (binäres Delta-Protokoll, immer verschlüsselt im Transit)
        │
        ├─ Lokaler Daemon: mehrere Clients/Agents am selben Container (kein Netz)
        └─ ZERO-KNOWLEDGE SaaS (Blob-Store): kennt nur {verschlüsselte Blöcke,
           Größe, Account-Zuordnung}. Passwordless ZK-Auth (SRP-6a). Kein Klartext, je.
```

**Kernprinzip: Speicher ist von der Zugriffsform entkoppelt.** Dieselbe Engine mountet einen Ordner, läuft in-memory in einer Cloud-App oder dient als Session-Store. Die gesamte Intelligenz (Deltas, Merges, Krypto, Commits) lebt im Client / in der Engine. Das erfüllt Zero-Out-of-Band (alles Relevante im Substrat, nichts versteckt im Server) und Zero-Dependency (SaaS abschaltbar; rein lokal lauffähig).

---

## 3. Datenmodell

Fünf Bausteine, an Zeros Vokabular angelehnt, FS-konkret:

| sfs-Baustein | Was es ist | Zero-Mapping |
|---|---|---|
| **Fragment** | Fixed-size Chunk. Identität = (`uuid`, Fragment-Index, Version `B`), **kein** Content-Hash. | Fragment |
| **Superseding-Kante** | „Version B verdrängt A" — gerichtete, kausal geordnete Strong-Kante. Die Lineage *ist* die Versionsgeschichte. | Strong-intrinsisch über Zeit / T4 Lineage |
| **Byte-Delta** | Physischer Unterschied A→B auf Byte-Ebene (keine Zeilen). Repräsentiert als „welche Chunks änderten sich". | Track-Materialisierung (Tx) |
| **Strain** | Ein Verlaufs-Strang. Normalfall linear; bei Konflikt **spaltet** er sich; zwei Strains koexistieren sichtbar, optional später zusammengeführt. | Strain |
| **Commit / Scope** | **Benannter Cut** über die Delta-Lineage — auch nachträglich, beliebige Pfad-Teilmenge. Optionale Meta-Ebene, kein Pflicht-Schritt. Pinnt Historie dauerhaft. | Track (Subgraph mit Scope, Closure) |

**Speicher-Form (D-1, D-2, D-2b — entschieden):**
- **Fixed-size Chunking, `fragsize` pro Unit.** Alle Chunks einer Unit sind gleich groß, nur der letzte ist partiell. Vorteil: **O(1) Offset→Fragment** für bare-metal-Random-Access-Reads, und minimale Metadaten. Trade-off: ein Insert in der Dateimitte shiftet die Folge-Chunks (re-sync des Rests) — für den Dev-Workload vernachlässigbar (Code-Dateien klein, Shift bandbreiten-trivial; Game-Assets werden meist *wholesale* neu geschrieben, nicht mittig eingefügt). CDC wurde dafür bewusst aufgegeben.
- **Datei = geordnete Chunk-Liste** (Unit-Map), kleine Dateien werden gepackt. Ermöglicht partielles Lesen/Syncen.
- **`fragsize` zur Write-Time aus der Unit-Größe deriviert** (nicht aus fester Schwellen-Tabelle). *(Amendment 2026-07: die tatsächlich implementierte Ableitung ist eine **Exponenten-Treppe**, nicht `clamp(next_pow2(size/n))`.)* Der Exponent wächst als `10 + 2^k`, praktisch erreichbar sind `exp ∈ {12, 14, 18, 22}` (4 KiB … 4 MiB), geklammert in `[12, 22]`; die Fragmentzahl skaliert damit **~√unit_size** statt linear — z. B. 5 MiB → 20 Fragmente, 300 MB → `exp 22` (4 MiB) → **~75 Fragmente** (nicht ~2500). Gespeichert als **1-Byte-Exponent** (`fragsize = 1<<exp`); innerhalb einer Unit-Version konstant → Offset→Index bleibt `offset >> exp` (O(1)). Byte-Authority: `block.rs` (core) / `sfs_format.h` (kernel, byte-genau gespiegelt).
- **Konsequenz:** Wächst eine Unit über eine Power-of-Two-Grenze, ändert sich `fragsize` → die Unit wird neu gechunkt (alle Chunk-IDs neu, kein Delta-Gewinn über den Sprung). Seltener Randfall; für größen-stabile Dateien ist `fragsize` stabil und Deltas greifen normal.
- **Re-Chunk-History-Semantik (Amendment 2026-07-12, entschieden mit Sandra — Option B):** Ein Re-Chunk ist eine *Re-Fragmentierung derselben logischen Version*, **keine neue Inhaltsversion**. Beim Grenz-Sprung werden die alten Fragmente daher **nur dann** als evictable History (D-17) in den Eviction-Tail bewahrt, wenn sie **commit-gepinnt** sind (benannter Scope, vgl. D-3 / „Niemand committet etwas, außer er will einen benannten Scope ziehen"). **Nicht-gepinnte** alte Fragmente werden **sofort freigegeben** (zurück in den Allokator), nicht als History kopiert. Begründung: ohne benannten Scope ist die Vor-Rechunk-Fragmentierung identischer Bytes kein eigener Lineage-Punkt (D-3 würde sie ohnehin thinnen) — sie zu bewahren blähte nur transient den Tail (gemessen ~3,2× Write-Amplification bei Multi-Band-Streaming-Appends: 8,2 GiB physisch für 2,56 GiB logisch → ENOSPC-Risiko auf knappen Containern, Large-Seqwrite-Verlust gegen ext4). Commit-gepinnte Checkpoints bleiben unversehrt. Umsetzung (Byte-Authority): `stage_rechunk` (core) / `cow_rechunk` (kernel) evictet **gepinnte** alte Fragmente in die History und gibt **nicht-gepinnte** frei; on-disk-Bytes der neuen Geometrie unverändert.
- **Trade-off-Bilanz (bewusst gewählt):** Das *erste* Schreiben ist etwas teurer — nicht durch Chunking-CPU (fixed-size ist billiger als CDC, kein Rolling-Hash), sondern weil die Größe bekannt sein muss, um `fragsize` zu wählen (unbounded Streams: provisorische `fragsize` + ein Re-Chunk beim Finalize). Dafür ist der **Continuous-Sync billiger**: stabile Boundaries → nur die geänderten fixen Blöcke reisen, O(1) lokalisiert, Version-Book pro Unit winzig. Im agentic/Multi-Rechner-Workload (einmal schreiben, tausendfach syncen) ist das die richtige Bilanz.
- **Exakter EOF:** `last_frag_length` (≤4 B, da `< fragsize`) → Gesamtgröße = `(n-1) × fragsize + last_frag_length`.

**Ordnung & Konflikt (D-4 — entschieden):** **Sparse Version Vector pro Unit.** Jede Unit trägt einen Vektor `{host_alias → sync_id}`. Konflikt = zwei Versionen, bei denen keiner der Vektoren den anderen dominiert (nebenläufig) → Strain-Split. Derselbe Vektor ist zugleich **Sync-Cursor** („was ist neu seit X") und **P2P-Konsistenz-Check** — eine Struktur, drei Zwecke; P2P fällt damit aus dem Modell heraus, kein Bolt-on.

- `sync_id` ist 64-bit, strikt monoton pro Host. `host_alias` ist ein **16-bit lokaler Alias** in eine **Peer-Registry pro Container**, die `alias → volle (Krypto-)Identität` einmal abbildet (hält Recycling/Retirement/Signing-Keys zentral; 65k Peers/Container).
- **Granularität: pro Unit, nicht pro Chunk** — Konflikt/Supersession sind Eigenschaften der Unit; Chunks sind reiner Inhalt. Das Sync-Book skaliert mit Units, nicht mit Millionen Chunks.
- **Kein DVV nötig:** Dotted Version Vectors lösen nebenläufige Schreibvorgänge *derselben* Replica — den Fall serialisiert der lokale Daemon weg (eine `host_id` pro Daemon/Replica). Also genügt der schlichte sparse Vektor.
- `host_alias`-Vergabe pro Daemon/Replica; intra-Host-Schreiber (mehrere Agents) serialisiert der Daemon. Wall-Clock nur *als Anzeige*, nie als Ordnungs-Autorität.

**Ablauf eines Schreibvorgangs:**
1. Datei ändert sich → Re-Chunking ab der ersten geänderten Position (fixed `fragsize`), geänderte Chunks werden identifiziert.
2. Neues Fragment (neue Chunk-Liste) + **Superseding-Kante** auf den Vorgänger, Vektoruhr inkrementiert.
3. Neue Chunks verschlüsselt in den Block-Store geschrieben, an die Sync-Engine gereicht.
4. Lineage wächst automatisch — **inherent version control**. Niemand „committet" etwas, außer er *will* einen benannten Scope ziehen.

**Sichtbarkeit / Scoping auf Platte:** Hierarchische **`.sfsignore` / `.sfsinclude`** — gilt rekursiv für alle Unterordner, bis ein gegenteiliges File greift.

### Datenstrukturen (Graph-Loslösung)

Der „Filedata-Graph" ist **kein fetter Objekt-Graph**, sondern zerfällt in entkoppelte Tabellen — die *Graph-Loslösung*. Daten, Struktur, Versionierung und Kausalität sind getrennt und **unabhängig syncbar**. **sfs ist identity+version-adressiert** (`uuid`, Fragment-Index, Version) — *nicht* content-adressiert: Dedup ist weg (D-15), Change-Detection läuft über Fragment-Versionen (`B`), Integrität über die Cipher-Suite (D-7). Content-Hashing existiert nicht mehr (Key-Hashing fürs Indexieren bleibt).

| Struktur | Inhalt | Größe |
|---|---|---|
| **Block-Space** | Verschlüsselte fixed-size Chunks, **pro Unit im linearen Segment-Space** (D-14). Adressiert über Index+Version, nicht Hash. | die eigentlichen Bytes |
| **Unit-Map** | Pro Unit-Stream die **geordnete Fragment-Versions-Liste `B`** (Position = Fragment-Index, Wert = 64-bit Block-Version). | `n × 8 B` |
| **Sync-Book** | Pro Unit-Stream der Sparse Version Vector (Konflikt + Sync-Cursor). | `p × 10 B` |
| **Persistence-Store** | **Versionierungs-System** (MVCC): `(uuid, frag#, versionid) → Block-Version` (Lage + Länge + Cipher). Nur *geänderte* Blöcke je Version. Trägt Lineage + Time-Machine (D-3). | `~28 B` je geänderter Block-Version |
| **ID-Catalog** | `uuid → Unit-Record-Adresse`. Sparse ~5-stufiger Byte-Radix-Trie (D-18). Relocation schreibt hier. | siehe D-18 |
| **Key-Catalog** | **`raw_path_bytes → uuid`** (Amendment 2026-07-12: NICHT `hash128(path)` — die rohen Pfad-Bytes erhalten die lexikografische Ordnung, die D-13-Prefix-Listing/-Rename braucht; ein Hash zerstreut Geschwister-Pfade). Sparse Byte-Radix-Trie (D-18). Rename schreibt hier. | siehe D-18 |
| **Peer-Registry** | Pro Container: `host_alias (16-bit) → volle (Krypto-)Identität`. | einmal/Container |

- **Fragment** = fixed-size Chunk, identifiziert durch **Position** (Fragment-Index, 32-bit) in seiner Unit + seine **64-bit Block-Version `B`**. Kein Content-Hash.
- **`B` (Fragment-Version) hat zwei Jobs:** (1) **Change-Detection/Sync** — beim Write hochgezählt im `sync_id`-Raum des Hosts; Sync vergleicht `B` und schickt nur geänderte Blöcke (block-granularer Sync). (2) **Block-granularer Merge** — zusammen mit dem Unit-VV (D-4): der VV erkennt Nebenläufigkeit, `B` sagt *welche* Blöcke jede Seite anfasste → verschiedene Blöcke = Auto-Merge, derselbe Block = Konflikt. Feiner als das Unit-Level-Modell.
- **Kein Content-Hash, kein Dedup (D-15).** Cross-Unit-Dedup ist bei fixed-size ≈0/sinnlos (bräuchte absichtliche Mehrfach-Ablage derselben Sourcen); Cross-Container per D-9 (ZK) aus. **Integrität liefert die Cipher-Suite (D-7), nicht ein Hash.** **Cross-Version-Delta** (über `B`) und **Packing kleiner Dateien** (Block-Auslastung) bleiben.
- **Persistence-Store = Versionierungs-System (D-16).** MVCC keyed `(uuid, frag#, versionid)`; nur geänderte Blöcke je Version (Cross-Version-Delta); Unit @ V = je Position jüngster Eintrag `≤ V` (Rückwärts-Walk der Versions-Liste, kein explizites Range nötig). Inhärente Versionskontrolle, kein separates VCS; Lineage + Time-Machine (D-3) leben hier. Mutable Lage hier, *getrennt* von der signierten Unit-Map → Relocation/Trim/Compaction ohne Re-Signing.
- **Unit** = adressierbares Composite über dem Fragment — Datei, Document-Record, Session-Blob, KV-Wert. Eine Struktur, alle Surfaces.
- **Eine Unit = zwei Streams:** **Content-Stream** (Bytes) + **Metadaten-Stream** (POSIX/Windows: Mode, Owner/Group, Timestamps, Flags, Symlink-Ziel, xattrs/erw. ACLs als opaker Blob). Gleiche Mechanismen, selbstähnlich; Metadaten-Stream winzig (~1 Fragment). Nötig für treuen FS-Drop-in.
- **Unabhängige Lineage pro Stream (D-4b):** eigene VV-Komponente je Stream → `chmod`/`touch` ∥ Content-Edit ist kein Konflikt.
- **Unit-Metadaten-Record** = `uuid` (inode-artig, stabil über Versionen) + je Stream {Unit-Map (`B`-Liste) + Sync-Book + `fragsize_exp` (1 B) + `last_frag_length` (≤4 B) + Commit-Pin-Bitmap(s)} + Superseding-Parent-Pointer.
- **Pro Unit, common case (1 Schreiber):** `n × 8 B` (Map) + `10 B` (Sync-Book) + ~5 B Skalare — winzig, nicht im Lese-Hotpath.
- Per D-3 ausgedünnte / nicht mehr referenzierte Block-Versionen fallen in die Eviction (Abschnitt 7).

### Identität & Cataloge (D-18 — entschieden)

**`uuid` (stabil) und `path_key` (mutabel) sind getrennt** — dafür zwei Resolver, beide als **sparse Byte-Radix-Trie** (Fan-out 256, ~5 Stufen ≈ 1,1 Billion Einträge; nur so viele Hash-Bits gelaufen wie nötig):

- **Key-Catalog:** `raw_path_bytes → uuid` (Amendment 2026-07-12, war `hash128(path)`; Raw-Bytes wegen Prefix-Lokalität für D-13). **Rename schreibt nur hier** → Historie folgt der `uuid`, nicht dem Pfad.
- **ID-Catalog:** `uuid → Unit-Record-Adresse`. **Relocation schreibt nur hier** (D-14-Overflow billig).

- **`uuid` = OS-GUID (UUID128)**, koordinationsfrei erzeugbar egal auf welchem Gerät → keine zentrale Vergabe, keine Kollision. Erfüllt Offline-First/Zero-Dependency.
- **Trie-Knoten = Blöcke**, Subtrees verweisen auf **absolute Block-Adressen + Backup-Kopie** (crash-/korruptionsfest; passt zum atomaren Commit).
- **Hot-Path-Resolve:** beim *Open* `path → Key-Catalog → uuid → ID-Catalog → Adresse` (2 Trie-Walks, ~10 Schritte, danach gecacht); der Byte-Read selbst bleibt contiguous (D-14). UUID-native Surfaces (z. B. Doc-Store) überspringen den Key-Catalog.
- Hardlinks/Aliase = mehrere Path-Keys → selbe `uuid`.

### Keyspace statt Verzeichnisbaum (D-13 — entschieden)

Es gibt **keinen Verzeichnisbaum als Primitiv.** Der Container ist ein **flacher `path_key → unit`-Store**; der Pfad ist nur ein eindeutiger Key (Metadatum). „Ordner" entstehen *emergent*, indem eine FS-Surface den Key an `/` aufspaltet — wie ein Object-Store. Damit *ist* derselbe Container zugleich Document-Store, Blob-Store, KV-Store, Session-Store (andere Surface → andere Keys). Sehr Zero (Zero-Imposed-Topology: keine aufgezwungene Baum-Ordnung).

- **`uuid` (stabil, intern) ≠ `path_key` (mutabel, eindeutig).** Aufgelöst über die zwei Cataloge aus **D-18** (Key-Catalog `raw_path_bytes→uuid` [Amendment 2026-07-12, war `hash128`], ID-Catalog `uuid→Adresse`). Rename = nur Key-Catalog-Update, `uuid` bleibt → Historie/Lineage folgt der Unit, nicht dem Pfad. Hardlinks/Aliase = mehrere Path-Keys → selbe `uuid`.
- **Prefix-Listing (`ls /foo/`)** über den Key-Catalog (sortierte/trie-Traversierung des Pfad-Raums). Flach, kein Baum; selbst versioniert/gesynct.
- **Folder = metadaten-only Unit.** Eine Unit kann content-only, metadaten-only oder beides sein (die zwei Streams aus D-4b sind unabhängig). Ein Verzeichnis ist eine Unit am Key `foo/` **mit nur Metadaten-Stream, ohne Content** → trägt Unix/Windows-Rechte, Owner, Timestamps des Ordners, versioniert/signiert wie alles. Löst leere Verzeichnisse first-class (kein Hack-Marker).
- **Tradeoff Verzeichnis-Rename/Move = O(n):** Prefix von n Units neu schreiben (+ je Signatur). Klassischer Object-Store-Preis; alles andere wird dafür simpler. Optionale Prefix-Indirektion später möglich (holt ein Stück Baum zurück) — bewusst *nicht* im Kern.
- **Keyspace-Konflikt:** zwei Rechner legen denselben Key gleichzeitig an / renamen dorthin → Eindeutigkeits-Konflikt, vom Version Vector erfasst und als Strain-Split markiert.

---

## 4. Speed-Modell (Zwei-Pfad)

Zentrale Designentscheidung aus der Speed-Dedication: **„aktuell" und „Historie" sind physisch getrennte Pfade.**

**Hot Path — der Head ist inhärent materialisiert (D-5):**
- Durch das contiguous Head-Layout (D-14) gibt es *kein* Delta-Replay zum Head. Der Head **ist** die aktuelle Chunk-Folge im linearen Space. Keine Verdopplung: Head = lebende Chunks, Historie = aufgehobene alte Block-Versionen.
- Lesen = direkter Block-Read, **page-cache-freundlich**, on-read entschlüsselt mit Hardware-Krypto. Ziel: **bare-metal minus Entschlüsselung** — der einzige akzeptierte Overhead. *(Amendment: „mmap-fähig" gilt für den **Kernel-Treiber** (`sfs.ko`, echter Page-Cache/`->readpage`); der Rust-Core arbeitet über `pread`/`pwrite` und **lehnt mmap/O_DIRECT ab** — die mmap-Perf-Zielsetzung ist dort aspirational, nicht implementiert.)*

**Cold Path — Lineage nie im Lesepfad:**
- Aufgehobene alte Chunks, Superseding-Kanten, alte Strains in einer separaten **append-only** Struktur. Historie abrufen darf langsamer sein.

**Wie APFS/ZFS-Probleme umgangen werden:**
- **Kein CoW-Metadaten-B-Tree im Lesepfad.** Verzeichnis-Listing aus kompaktem In-Memory-Index, nicht aus On-Disk-Tree-Traversal (APFS' Schwäche bei vielen kleinen Dateien).
- **Write-Latenz entkoppelt:** Writes zuerst in append-only Log (schnelles `fsync`), Re-Chunking + Delta-Berechnung + Sync **asynchron** danach. Kein synchroner Write-Amplification-Stall wie bei ZFS-Sync-Writes.

**Block-Store-Substrat (D-6 — entschieden, beides):** **Container-Datei über dem Host-FS** (`pread`/`pwrite`; `mmap`/`O_DIRECT` waren geplant, sind im Core aber **bewusst abgelehnt** — der Kernel-Treiber liefert den echten Page-Cache-Pfad) als Default — portabel über alle OS, deckt Folder-Mount, in-memory und embedded mit *einem* Format („Projektordner einhängen" lebt ohnehin innerhalb eines Host-FS). **Eigenes Block-Device-Backend** als späterer optionaler Hochleistungspfad für Appliance/Server.

### Container-Layout (D-14 — entschieden: segment-strukturiert, media-agnostisch)

**Layout-Default (Amendment 2026-07-12, entschieden mit Sandra): statisches 3-Regionen-Layout — Catalog-front.** `[Catalogs-Head (wächst vorwärts)][Live-Units (front-to-back)][Eviction-Tail (wächst rückwärts)]`. Begründung: sfs zielt auf Flash/NVMe (keine Seek-Strafe) + metadaten-schwere agentic Workloads; ein front-geclusterter Katalog hält die heißen Trie-Knoten (Prefix-`ls`, Rename, Resolve) beisammen und cache-warm, und der Dual-Random-UUID-Katalog passt ohnehin nicht sauber auf ein Block-Group-Segment-Modell. Auf **Lücken ausgelegt** (In-Place-Wachsen) *und* **trimbar**. Grundsatz: nicht gegen die Hardware kämpfen — aligned I/O, physisches Placement dem Controller/der FTL überlassen.

**Dokumentierter Skalierungspfad (nicht Default): wiederholende Segmente** `[Segment-Index für x Units][linearer Space]…` (ext4-Block-Group-artig) — sinnvoll erst, wenn HDD/Riesen-Cold-Scale anvisiert wird oder Katalog-Contention zum Parallelitäts-Flaschenhals wird. Bewusst zurückgestellt: der Seek-Vermeidungs-Vorteil ist eine HDD-Sache, die Flash gratis macht, und würde die Katalog-Lokalität opfern, die der Zielworkload braucht.

- **Linearer Unit-Space = contiguous materialisierte Heads.** Der Head einer Unit liegt zusammenhängend und aligned → bare-metal-naher sequentieller Read (deckt D-5). Superseded Chunks/Deltas (Cross-Version-Historie) leben im Cold-Path; etwas Head-Redundanz wird bewusst gegen Read-Lokalität getauscht (dieselbe D-5-Bilanz: Platz gegen Speed).
- **Alignment first:** Index und Daten am Basis-Block ausgerichtet (z. B. 4 KB = fragsize-Floor = typische Page/Sector-Größe). Aligned I/O ist auf *jedem* Medium controller-freundlich.
- **Media-agnostisch — nicht in eine Richtung optimieren:** kein gerätespezifisches physisches Layout. Das physische Placement übernimmt der **Storage-Controller / die FTL** (Flash/NVMe: Wear-Leveling/Placement; HDD: Sektoren; RAM: Page-Cache). Ein Layout für RAM, Flash, NVMe und HDD.
- **Wachstum/Overflow:** in die Lücke wachsen; reicht sie nicht, wird die Unit relociert → nur der **Index-Eintrag `unit_id → Offset`** ändert sich, `unit_id` bleibt stabil (billig).
- **Trimming:** freigewordene Bereiche per Hole-Punch/TRIM zurückgeben (im FS-Fall über die sparse Container-Datei aus D-6), ohne den Container neu zu schreiben.
- **In-RAM-Fall:** dasselbe Layout = Arena mit Lücken; Trimming = free. Bestätigt Media-Agnostik (deckt den Embedded/in-memory-Surface aus Abschnitt 1).

### Live- vs History-Segregation (D-17 — entschieden)

Eine Unit ist im Storage **ein möglichst zusammenhängender Bereich** — nur ihr aktueller Head. Superseded Block-Versionen kleben **nicht** interleaved in der Unit, sondern liegen **außerhalb**, im History-Bereich. So bleibt der Lese-Hotpath ein sauberer contiguous Scan.

- **Live-Bereich (Head):** contiguous, fixed-size Block-Slots + Wachstums-Gap (D-14), **bare bytes ohne interleaved Header**. Ein geänderter Block ist exakt `fragsize` → überschreibt **in-place** seinen Slot, der Head bleibt zusammenhängend. Der **alte** Block wird vorher in den History-Bereich kopiert.
- **History-Bereich:** **append-only**, **self-describing** evictable Blocks: `{ uuid, frag#, length, timestamp(UTC), A=commitish, B=block-version } + raw bytes`. Per D-3 time-thinned, commit-gepinnte übersprungen.
- **Warum das fixed-size (D-1) liebt:** gleiche Slot-Größe → In-Place ohne Fragmentierung. Nur **Wachstum** braucht Gap/Relocation (D-14); Fragmentierung/Compaction ist ein nachgelagertes Problem (Units umkopieren bzw. Nachbar weicht).
- **Crash-Atomicity:** Copy-out-alt → In-Place-neu → Persistence/Version/Signatur committen *atomar* über den Container-Header (D-20).

### Container-Header (D-20 — entschieden)

Der Anfang des Containers (nach dem **Magic**) ist der Anker: `encryption-backend-marker` (welche Cipher-Suite, D-7) + **Params** (`max fragment size`, `eviction strategy` für D-3) + Pointer auf die Catalog-Roots (D-18) + Writer-Set-Ref (D-12). Der Header ist der **atomare Commit-Punkt** (double-buffered: zwei Slots bei Offset 0 und 4096, inaktiven schreiben; *(Amendment: der aktive Slot ist der **CRC-valide mit höchstem `commit_seq`** — **seq-wins, kein separater Active-Index-Pointer/Flip)*** → Crash vor dem Commit = alter konsistenter Stand, danach = neuer. Crash-Sicherheit ohne Journaling-Komplexität.

### Allokation & Online-Defrag (D-21 — entschieden)

Drei Regionen im Container: **Head = Catalogs** (wächst vorwärts) · **Live-Units** (füllen front-to-back, block-aligned + Sub-Block-Packing) · **Eviction-Tail** (wächst rückwärts vom Ende). Das löst die in D-14/D-17 offen gelassene Fragmentierung.

- **Extension-Write** (Unit wächst über ihre Grenze): **first-fit** freien Platz suchen (+ Reserve), **nur die Extension-Blöcke** dort schreiben, ein **Temp-/Extension-Head** im Head vermerken → Lesen/Schreiben über eine kleine **vtable** (Segment-Offsets). Pro Extension ein vtable-Eintrag mehr; echte Lücken (wie FAT) entstehen, werden aber laufend gefixt.
- **Background-Defrag** kopiert die Unit contiguous um, dann: **erst atomarer Base-Adr-Switch im ID-Catalog, dann Temp-Removal** → doppelt sicher (alt-via-`uuid`-Record *und* Temp überleben bis zum Switch; ein Crash ist immer recoverable). vtable kollabiert auf 1 Eintrag.
- **Relocation berührt nur den ID-Catalog** (`uuid → Adresse`); Key-Catalog und alle Referenzen bleiben (uuid stabil). Aliases = mehrere Key-Einträge → eine uuid → ein Record (~10-Step-Resolve), keine Record-Duplikation.
- **Hot/Cold-Gradient (emergent, *keine* aktive Policy):** dicht gepackter Cold-Front hat wenig Lücken → Extensions landen von selbst tail-wärts, Defrag verdichtet Cold front-wärts → Stale sammelt sich vorn, Hot wandert Richtung Ende. Das entsteht **emergent** aus der Freiraum-Dynamik. **Bewusst kein aktives Key-Clustering:** das ginge nur entlang Pfad-Keys (Nachbarn nah beieinander), würde aber die **Surface-Agnostik brechen** (sfs adressiert auch über uuid/Session/Doc-Keys, nicht nur Pfade); zudem ist auf Block-Level bei vielen kleinen Dateien korrektes Clustern kaum erreichbar.
- **vtable-Kosten (gescoped):** viele Mini-Extensions in Folge → vtable wächst schnell, bis Defrag kollabiert. Akzeptiert — sfs ist *kein* Medien-Recording-FS. Optionale Milderung: Writes vor dem Flush coalescen.
- **„Full"-Policy:** treffen Head/Live/Tail aufeinander → **Backing-File wachsen** (sparse, D-6) oder härter eviktieren (Tail ist durch D-3 ohnehin gedeckelt).

### Self-describing Format & Scan-Recovery (D-22 — entschieden)

Jeder **Unit-Head hat eine strikte Struktur mit Start-Magic + Head + CRC**; ebenso sind Evicted-Blocks self-describing (D-17). Damit ist der Container **aus den Rohdaten rekonstruierbar**:

- **Scan-Recovery:** unallocated/rohe Bereiche durchscannen, an jedem Block-Start `Magic + Head + CRC` prüfen → verlorene Einträge (z. B. bei beschädigtem Catalog) werden gefunden und neu indiziert.
- Zusammen mit den **Backup-Trie-Knoten (D-18)** und den self-describing Evicted-Blocks ist sowohl der aktuelle Stand *als auch* die Historie wiederherstellbar — auch wenn Catalogs/Header beschädigt sind. Robustheit „tief auf FS-Ebene".

---

## 5. Konsistenz & Konflikte

Binäres, byte-orientiertes Modell — keine Zeilen-Semantik (eine UI darf Bytes als Text rendern, das Modell kennt nur Bytes/Chunks).

- **Strain-Split bei Divergenz:** Empfängt ein Rechner ein Delta, das laut Vektoruhr nebenläufig ist (setzt nicht auf seine aktuelle Version auf), spaltet sich der Strain. Beide Versionen bleiben gültig; die Datei erhält einen **Marker + Message**. Nichts wird je still überschrieben.
- **Resolution auf Changeset-Ebene (Gruppe), nicht pro Item.** Konflikte treten in Gruppen auf — zwei Agents auf zwei Maschinen im selben Projekt, oder ein agentic Swarm als Clients am selben lokalen Container (über den Daemon, auch auf einem Rechner).
- **Resolution-Surface:** Changeset schneiden/bestimmen → vergleichen → optional auflösen. **Kein Zwang** — ungelöste Divergenz bleibt als markierter, gespaltener Strain bestehen und kann später zusammengeführt werden.
- **Merge** erzeugt ein neues Fragment mit *zwei* Superseding-Kanten (zwei Strains führen zusammen).
- **Block-granular (über `B`):** Der Unit-VV erkennt Nebenläufigkeit; die Fragment-Versionen `B` sagen, *welche* Blöcke jede Seite anfasste. Änderten beide Seiten *verschiedene* Blöcke → **Auto-Merge**, kein Strain-Split. Nur Überlappung am selben Block ist echter Konflikt. Das senkt False-Konflikte drastisch (zwei Agents, die verschiedene Teile derselben großen Datei bauen).

---

## 6. Sync & Zero-Knowledge-SaaS

**Sync-Protokoll (binär, delta-orientiert):**
- Client und SaaS tauschen **nur verschlüsselte Blöcke + minimale Sync-Metadaten** (Version-Vectors + Fragment-Versionen `B`). „have/want"-Abgleich auf **Versionen** (block-granular über `B`) — der Server lernt nichts über Inhalt.
- **Push:** fehlende verschlüsselte Blöcke + verschlüsselte Superseding-/Strain-Struktur hochladen. **Pull:** „was ist neu seit Vektoruhr-Stand X", fehlende Blöcke laden, Head lokal materialisieren.
- **Immer verschlüsselt im Transit** (TLS) *und* at-rest (Blöcke clientseitig vorverschlüsselt).

**Krypto-Agilität (D-7 — entschieden, pluggbares Backend):**
- Der **Cipher-Mode ist Teil eines pro Container verhandelbaren, austauschbaren Krypto-Backends** — nicht fix verdrahtet. *(Amendment: die Suite steht als **Header-Feld pro Container** (`cipher` / `content_cipher`) plus optionalem **Per-Record-Override** (`content_suite`) — **nicht** als Per-Block-Tag. Seit v12/D4c leitet der Container **einen** Content-Key ab; Eindeutigkeit trägt der Per-Fragment-Nonce, nicht Per-Block-Keys.)*
- Beim Übergang zwischen Rechnern/OS/Architekturen wird aufs **„common optimum"** gewechselt: lieber eine gemeinsame, evtl. schwächere HW-Beschleunigung, die alle Geräte können, als die beste, die nur ein Gerät hat. Re-Encrypt-Pass blockweise, ohne dass der Server je Klartext sieht.
- **Integrität ist Eigenschaft der Cipher-Suite — kein separater Hash:** Da Content-Hashing entfiel (D-15/D-16), liefert die *gewählte* Suite die Tamper-Evidence. **AEAD** (z. B. GCM, Auth-Tag pro fixed-size-Chunk) für Multi-User/untrusted/P2P — Manipulation lässt die Entschlüsselung selbst fehlschlagen, kein dangling Hash, der nur „passt nicht" sagt. **XTS** (schnellster Random-Access, keine Auth) für Single-User/trusted, wo Medium-ECC + TLS versehentliche Korruption abdecken. Pro Container wählbar (Teil der Krypto-Agilität).

**Zero-Knowledge-SaaS (D-8, D-9 — entschieden):**
- **Rolle: Blob-Store** (sternförmig) als Basis + **lokaler Daemon** für mehrere Clients/Agents am selben Container (kein Netz). **P2P/Relay** als spätere Erweiterung.
- Speichert ausschließlich `{verschlüsselte Blöcke, Block-Größen, Account-Zuordnung, verschlüsselte Struktur-Metadaten}`. **Keine Dateinamen, keine Pfade, kein Klartext** — Pfade/Namen sind selbst verschlüsselte Fragmente. Server-Funktion: Verfügbarkeit + Transport + Abrechnung nach physischer Größe. „Beweisbar sicher" wörtlich: der Betreiber *kann* kryptographisch nicht zugreifen.
- **Strikt nur Blobs pro Account.** **Kein Cross-User-Dedup** (würde Gleichheit leaken → Confirmation-of-File-/Fingerprinting-Angriffe) — und auch kein Cross-Unit-Dedup *innerhalb* eines Containers, da ≈0/sinnlos (D-15). **Keine Server-Suche.** Suche = clientseitiger Index, als verschlüsselte Blobs gesynct.
- **Auth: SRP-6a** (Secure Remote Password, wie im Ifyna-Backend). Server speichert nur einen Verifier, sieht nie das Passwort. *(Amendment: SRP-6a authentifiziert die Session; den **Container-Root-Key** wrappt ein **eigenständiger Argon2id(password)-KEK** (D8c) — beide Pfade starten am Passwort, aber der Wrap-Key ist nicht das SRP-Session-Secret.)* Ein Login entsperrt lokal die Krypto, ohne dass der Server je einen Schlüssel sieht.

**Key-Recovery (D-10 — entschieden):** **Recovery-Code** (offline beim User) als Default + optionale **Shamir-Multi-Device-Key-Shares** für Power-User. Beide ZK-erhaltend (Rekonstruktion clientseitig). **Kein server-gehaltenes Escrow** (würde ZK brechen).

**Multi-Tenant-Isolation (D-11 — entschieden):** **Pro-Account-Isolation** als Default (Server sieht Größen pro Account → Abrechnung ok; ohne Cross-Account-Dedup kleine Korrelations-Fläche). **Optionales Padding** pro strikt deklariertem Container. ORAM bewusst *nicht* als Default.

### Multi-User & Zugriff (D-12 — entschieden: Shared Container)

Die Basis ist **Single-User** (mehrere Geräte einer Identität, ein Schlüsselraum, „Zugriff" trivial). Multi-User = **mehrere Identitäten teilen sich einen Container** (Team-Workspace, wie ein geteilter Ordner / Repo mit mehreren Committern). Zugriff ist **binär auf Container-Ebene**: kein Container-Zugriff → der Container existiert für dich schlicht nicht. Sicherstes, schmerzärmstes Modell.

**Rollen read / read-write — kryptographisch, nicht server-durchgesetzt** (der Server ist blind):
- **read** = Besitz des (symmetrischen) **Content-Keys** → kann entschlüsseln/lesen.
- **read-write** = zusätzlich Besitz eines **Signing-Keys, dessen öffentliche Identität im Writer-Set des Containers steht**. Writes sind signiert; alle akzeptieren nur Updates mit gültiger Writer-Set-Signatur.
- **read-only** = hat den Content-Key, aber **keine akzeptierte Signing-Identität** → liest, aber jeder Write wird von den anderen verworfen.
- **kein Zugriff** = kein Content-Key → Chiffretext, faktisch absent.
- *(write-only / Drop-Box-Semantik — schreiben ohne lesen — via asymmetrischer Per-Write-Verschlüsselung möglich; optional, nicht Kern.)*

**Folge: Signing wird im Multi-User-Fall Pflicht** (Single-User war es optional). Das Writer-Set ist selbst signierte Container-Metadaten, von einer Owner/Admin-Identität verwaltet. Die **Peer-Registry** hält jetzt mehrere *Nutzer*-Identitäten (je mit mehreren Geräten); `host_alias` bleibt pro Gerät/Daemon, die Zuordnung Gerät→Nutzer + die Write-Signatur geben **authentifizierte Attribution** für Strains/Konflikte.

**Signing-Granularität: pro Unit-Version, nicht pro Fragment.** Signiert wird das **Versions-Record** der Unit (bzw. des Streams) — es enthält Writer-Identität, `uuid`, Version-Vector und die **Unit-Map** (= Liste der Fragment-Versionen `B`). **Der Parent-Pointer wird NICHT mit-signiert** (Amendment 2026-07-12): er ist eine replica-lokale Blockadresse (ändert sich pro Replica nach Relocation/Defrag), würde also eine gesyncte Signatur replica-spezifisch und cross-Replica-unverifizierbar machen und D-16s „Relocation ohne Re-Signing" brechen. Parent ist stattdessen über die adress-gebundene GCM-AAD der Storage-Schicht (per-Replica) geschützt. Damit:
- **Eine Signatur pro Write, nicht pro Chunk** — die signierte Map + Version-Vector binden die Write-Autorität an genau diesen Stand. **Content-Integrität via AEAD-Cipher (D-7)**, Write-Authentizität via Versions-Signatur — zwei Schichten, keine Redundanz.
- **An die Version gekoppelt** (der signierte **VV + uuid + Unit-Map** IST die kausale Position; Amendment 2026-07-12: Pinning trägt der VV, nicht der Parent) → nicht auf eine andere Lineage-Position umdeutbar oder replaybar; pinnt genau einen Punkt im Strain-DAG. Commit-Pinning (D-19) referenziert Versionen per VV-abgeleiteter Version-ID, nicht per Parent-Adresse — ist also unberührt.
- **Attribution:** jeder Strain-Head trägt die Signatur seines Urhebers → eindeutig, wer welche Konflikt-Seite erzeugt hat.
- **D-4b-konform:** ein Write signiert die jeweils fortgeschrittene Stream-Version (Content- *oder* Metadaten-Version); ein `chmod` signiert nur das Metadaten-Versions-Record.

**Revocation** = forward Re-Key (Content-Key + Writer-Set rotieren). Inhärente Grenze: bereits gelesene/gecachte Daten sind nicht zurückholbar; ein Read-Berechtigter konnte immer leaken — nur zukünftig ausschließbar.

**Optionale ZK-erhaltende Server-Hilfe:** Der blinde Server *kann* unsignierte/nicht-autorisierte Writes ablehnen, indem er Signaturen gegen das öffentliche Writer-Set prüft — ohne je Klartext zu sehen. Spart Bandbreite/Storage; Korrektheit kommt aber von der Client-Verifikation.

---

## 7. Retention / Time-Machine (D-3 — entschieden)

Statt „alles für immer" oder hartem Pruning: **zeitliches Ausdünnen** der unbenannten Historie nach einem Time-Machine-artigen Plan, während **Commits feste, nie geräumte Punkte** sind (Reachability-Pinning).

Beispiel-Plan (konfigurierbar):
- **bis 1 h:** alle Änderungen (feingranular)
- **bis 24 h:** stündlich
- **bis 14 Tage:** täglich
- **darüber:** monatlich → jährlich

Für schnell ändernde Daten (Game-Assets, generierte Artefakte) verhindert das, dass Autosave-Churn den Store sprengt; für alles, was bewusst per **Commit/Scope** gepinnt ist, bleibt die Historie lückenlos („Sourcesave" dort, wo es zählt). Alles, was von einem Commit oder lebenden Strain-Head erreichbar ist, überlebt jedes Thinning.

> *Amendment (Stand 2026-07-20): Der frei konfigurierbare, kontinuierliche Time-Machine-Plan oben ist die **Zielarchitektur**. Implementiert und persistiert sind aktuell **drei feste Eviction-Strategien** (im Header-Param, D-3/D-17); das Thinning läuft **nicht kontinuierlich im Hintergrund**, sondern wird **explizit per CLI (`sfsctl evict`) angestoßen**. Physisches **TRIM/Hole-Punch** (D-17) ist zurückgestellt — freigegebene Bereiche kehren in den Allokator zurück, werden aber noch nicht an das Host-FS/Device zurückgegeben. Die Reachability-/Commit-Pinning-Semantik ist voll implementiert.*

### Commits & Versionen (D-19 — entschieden)

Ein **Commit** ist ein optionaler, benannter Snapshot — die Meta-Ebene über der immer-mitlaufenden Versionierung („Commit, wenn du willst").

- **Commits sind reservierte Units** unter `.sfs/commits/<commitish>` → erben **Sync + Signatur + Versionierung gratis** (self-similar). `git log` = Prefix-Scan `.sfs/commits/`; Commit-DAG = Commit-Units referenzieren Parent-Commits. `.sfs/` ist reservierter System-Namespace (im FS-Mount versteckt).
- **Inhalt:** `{ title, message, commitish, parent(s) } + pro Unit (uuid, content_version, meta_version)` — snapshottet beide Stream-Versionen (D-4b).
- **Lazy-CoW-Pinning (löst Eviction-Schutz tief auf FS-Ebene):**
  1. *Commit anlegen:* im Unit-Head eine **Commit-Pin-Bitmap** (1 Bit/Block: „unverändert seit Commit"), alle aktuell lebenden Blöcke gesetzt — *keine Datenkopie* (128× kleiner als ein 128-bit-Slot/Block).
  2. *Späterer Write auf Block i:* Bit i löschen; der verdrängte alte Block wandert in den History-Bereich und bekommt `A=commitish` gestempelt → **nicht evictbar**.
  3. *Unit @ Commit rekonstruieren:* Bit gesetzt → Live-Block (unverändert); sonst → History-Rückwärts-Walk über `B` zum Stand `≤` der Commit-Version.
- **Eviction-Wahrheit:** „von einem Commit erreichbar" (aus den Commit-Units ableitbar); Bitmap und `A`-Stempel sind der schnelle Cache. Time-Machine (D-3) thinnt alles Unbenannte, lässt Commit-Gepinntes stehen.

---

## 8. Zero-Pillar-Mapping

| Pillar | Wie sfs es erfüllt |
|---|---|
| Zero-Lock-In | Offenes Container-Format, voll lokal lauffähig, SaaS abschaltbar → Daten gehen mit. |
| Zero-Hollow-Foundation | Engine + Format + Protokoll als offene Referenz; Kommerz baut auf Hosted-SaaS auf, nicht darin. |
| Zero-Notation-Lock-In | FS-Surface spricht normale Datei-Semantik; Graph-API ist optional. |
| Zero-Imposed-Topology | Kein globaler Namespace erzwungen; Container sind lokale Authority-Cluster. |
| Zero-Implicit-Sharing | Server sieht nichts; Sichtbarkeit ist explizit (geteilte Keys, verschlüsselte Strukturen). |
| Zero-Context-Loss | Superseding-Lineage + Strains reisen mit; Sync streift nie Historie ab. |
| Zero-Out-of-Band | Aller Zustand (Versionen, Strains, Commits) liegt im Container, nichts versteckt im Server. |
| Zero-Overhead | Einfacher Fall = einfach (Ordner mounten, fertig); Commits/Strains nur wenn gewollt. |
| Zero-Dependency | SaaS ersetzbar (Blob-Store-Interface), P2P-/Local-only-Betrieb möglich. |

Strenge-Position: **wählbar pro Container** (Zero-vage bis Zero-strikt). Krypto-Agilität, optionales Signing und optionales Padding sind die Stellschrauben auf dem Spektrum.

---

## 9. Surfaces im Detail

Eine Engine, vier Betrachtungswinkel auf denselben Container:

1. **FS-Mount** (FUSE/NFS) — „Projektordner als sfs einhängen". Primär-Surface für OS-Apps. Head-Reads bare-metal-nah.
2. **Embedded / in-memory** — Cloud-SaaS-App nutzt sfs-Container im RAM und synct gegen Offsite-Storage. Kein Mount nötig.
3. **Graph-API / SDK** — Agenten lesen Fragmente/Deltas/Strains nativ; auch Session-Storage einer Server-App.
4. **App-nativ** — z. B. iOS mit eigener Primär-Surface auf denselben Container.

---

## 10. Decision-Point-Index (final)

| ID | Entscheidung | Ergebnis |
|---|---|---|
| D-0 | Name / das „S" | `sfs` (Engine, parallel zu zfs/apfs) + **Zero-FS** (Familien-Slot); S multivalent |
| D-1 | Chunking | **Fixed-size, `fragsize` pro Unit** (O(1) Offset→Fragment; CDC bewusst aufgegeben) |
| D-2 | Fragment-Granularität | **Chunk-Liste (Unit-Map) + Packing kleiner Dateien** |
| D-2b | fragsize-Wahl | **Zur Write-Time aus Unit-Größe deriviert** (Power-of-Two, Ziel: bounded `n`, Floor 4 KB), 1-Byte-Exponent |
| D-3 | Retention | **Time-Machine-Thinning + Commits als feste Punkte** (Reachability-Pinning) |
| D-4 | Ordnung & Konflikt | **Sparse Version Vector pro Unit** (`p × 10 B`, 16-bit Host-Alias + Peer-Registry); = Sync-Cursor + P2P-Check; Zeit nur Anzeige |
| D-4b | Stream-Lineage | **Unabhängige Lineage pro Stream** (Content vs. Metadaten) → orthogonale Merges konfliktfrei |
| D-5 | Head-Strategie | **Inhärent materialisiert** (contiguous Head-Layout, kein Replay) |
| D-6 | Block-Store-Substrat | **Container-Datei jetzt + Block-Device-Backend später** |
| D-7 | Krypto & Integrität | **Pluggbares Cipher-Backend pro Container**: AEAD (Multi-User/untrusted) / XTS (Single-User/trusted). Integrität = Cipher-Suite, **kein Content-Hash** |
| D-8 | SaaS-Rolle | **Blob-Store + lokaler Daemon**, P2P später |
| D-9 | Blinde Server-Dienste | **Strikt nur Blobs pro Account**, kein Cross-User-Dedup, keine Server-Suche |
| D-10 | Key-Recovery | **Recovery-Code + optionale Shamir-Key-Shares**, kein Server-Escrow |
| D-11 | Multi-Tenant-Isolation | **Pro-Account + optionales Padding**, ORAM nicht Default |
| D-12 | Multi-User & Zugriff | **Shared Container**, binärer Container-Zugriff, Rollen read/read-write kryptographisch (Content-Key + Writer-Set-Signatur); Signing dann Pflicht |
| D-13 | Keyspace | **Flacher `path_key → unit`-Store, kein Verzeichnisbaum**; `uuid`≠`path_key` (D-18); Folder = metadaten-only Unit; Dir-Rename O(n) |
| D-14 | Container-Layout | **Statisches 3-Regionen-Layout (Catalog-front)** als Default (Amendment 2026-07-12: Flash + metadaten-schwer); wiederholende Segmente als dokumentierter HDD-/Skalierungs-Pfad; aligned, gap+trim; Heads contiguous; physisches Layout dem Controller/FTL überlassen |
| D-15 | Dedup-Scope | **Kein globaler Dedup-Store** (Cross-Unit ≈0/sinnlos, Cross-Container per D-9 aus); **kein Content-Hash** — Change-Detection via Fragment-Version `B`, Integrität via Cipher (D-7); Cross-Version-Delta + Packing bleiben |
| D-16 | Persistence-Store | **Versionierungs-System** (MVCC, `(uuid,frag#,versionid)→Block-Version`); inhärente Versionskontrolle, getrennt von der signierten Unit-Map |
| D-17 | Live/History-Segregation | **Live-Head contiguous (in-place, bare bytes), History append-only + self-describing**; evicted Block `{uuid,frag#,length,ts,A=commitish,B}` |
| D-18 | Identität & Cataloge | **`uuid` (OS-GUID) ≠ `path_key`**; zwei sparse Byte-Radix-Tries: Key-Catalog **`raw_path_bytes→uuid`** (Amendment 2026-07-12, war `hash128(path)` — Raw-Bytes für D-13-Prefix-Lokalität), ID-Catalog `uuid→Adresse`; Subtree→Absolut+Backup |
| D-19 | Commits & Versionen | **Commits als `.sfs/commits/`-Units** (sync/sign gratis); Lazy-CoW-Pinning via Commit-Bitmap + `A`-Stempel |
| D-20 | Container-Header | Magic + Encryption-Marker + Params (max fragsize, eviction) + Catalog-Roots + Writer-Set; **double-buffered atomarer Commit-Punkt** |
| D-21 | Allokation & Online-Defrag | **3 Regionen** (Catalogs-Head / Live-Units / Eviction-Tail); Extension via first-fit + Temp-Head + vtable; Defrag: atomarer Base-Adr-Switch dann Temp-Removal, **nur ID-Catalog**; **emergenter** Gradient (Stale vorn, Hot hinten), kein aktives Key-Clustering (Surface-Agnostik) |
| D-22 | Self-describing & Recovery | Unit-Head **Magic + Head + CRC** → **Scan-Recovery** aus Rohdaten; mit Backup-Trie-Knoten (D-18) + self-describing Evicted-Blocks (D-17) voll rekonstruierbar |
| D-23 | DB-Surfaces | **NoSQL nativ** (db-Head-KV/Typ-Extension, Record=Unit `property→type:value`, Index `(store,property,value)` via Trie). Siehe Addendum A (§12). *(SQL-via-Engine-Backing verworfen — kein Fit auf FS-Ebene.)* |
| — | Familien-Verhältnis | **Option A:** sfs absorbiert Sync/Backup/Share als Sichten |

---

## 11. Nächste Schritte

**Erste Implementierungs-Scheibe (Vorschlag):** Core-Engine mit Container-Datei-Backend (D-6), fixed-size Chunk-Store size-tiered (D-1/D-2/D-2b), inhärent materialisiertem Head (D-5), Version-Vector-Lineage pro Unit (D-4), **lokal-only ohne SaaS** — also ein schneller, versionierender lokaler Container ohne Sync. Damit sind „Speed" und „inherent version control" früh erlebbar, bevor die Verteil-Komplexität dazukommt.

**Zweite Scheibe:** Sync-Engine + Zero-Knowledge-Blob-Store + SRP-6a-Auth + Krypto-Agilität + Strain-Split/Resolution-Surface.

**Dritte Scheibe:** FS-Mount-Surface (FUSE/NFS), Time-Machine-Retention, Recovery-Mechanismen.

**Familie:** Eintrag für Zero-FS in `zero_concept/docs/projects/` anlegen; Skizzen Zero-Sync/Backup/Share als Sichten auf Zero-FS zurückstufen.

---

## 12. Addendum A — NoSQL-Surface (KV/Document)

Eine NoSQL-Datenbank ist eine **Surface über dem bestehenden Substrat**, mit *einer* kleinen Kern-Erweiterung (D-23).

**Modell:**
- **Adressierung:** `store + primary-id → Unit` (Store = Collection, `pk` = Datensatz-ID).
- **db-Head-Extension:** markiert die Unit als **KV-Record** (statt Bin-Blob) und trägt `store` + `pk`. Der Content ist eine **platte typisierte Map `property → type:value`**.
- **Records huge oder winzig** — egal; **Revisionen geschenkt** (MVCC, D-16).

**Query „by store + property":**
- Index `(store, property, value) → pk` über die **Trie-Infra (D-18)** — wiederverwendete Struktur, kein neues Subsystem.
- Einfache `prop = value`-Lookups = direkter Index-Hit (billig). Komplexe Abfragen (Multi-Property, Aggregation, Sort) brauchen Query-Planung = Engine-Arbeit, aber die Indizes liegen vor.

**Kosten & Bonus (ehrlich):**
- **Index-Pflege = Write-Cost** — jeder Insert/Update fasst die betroffenen Property-Indizes im selben atomaren Commit an (D-20).
- **Property-granularer Merge fast geschenkt:** fallen Properties eines Records in *verschiedene* Blöcke, mergt Block-Merge (`B`, D-16) konkurrierende Property-Edits automatisch; winzige Records (ein Block) bleiben Unit-Level-Konflikt.
- **Transaktionen** = atomare Changesets über das Commit-Primitiv (D-20).

---

## 13. Addendum B — WASM-Ausführungsmodell (Browser / modulfrei)

Dasselbe Container-Format läuft **vollständig im Browser/WASM** über die Engine als reine In-RAM-Surface (`crates/sfs-wasm`) — kein Kernel-Modul, kein FUSE, kein Server. Der portable Pfad neben Kernel und FUSE; Format-identisch, damit ein hier erzeugter Container von Datei/Kernel/FUSE gelesen wird und umgekehrt.

**Lesen (`SfsReader`):** öffnet, listet und liest über die verschlüsselten (`none` / `xts` / `gcm`) **und** signierten (WriterSet) Formate — dieselbe `Engine::snapshot`-Sicht wie ein Datei-Container.

**Schreiben (`SfsWriter`, in RAM):** erzeugt, schreibt und **signiert** Container komplett im Speicher und gibt die persistierbaren Bytes an JS zurück (`snapshot`). Drei Schlüsselmodi:
- **Raw-Key** — 32-Byte-Root-Key direkt.
- **Passwort** — zufälliger Argon2id-Salt, in den Header gestempelt (v12/D8c), sodass ein Reopen per Passwort ableitet.
- **Signed** — Ed25519-Writer-Key aus einem Seed (der Seed verlässt den Aufrufer nie); jeder Record wird signiert, ein Reopen verifiziert fail-closed.

**Ehrliche Grenzen (WASM-spezifisch):**
- Der parallele Fragment-Decrypt-Pool von `sfs-core` liegt auf `std::thread`; ohne WASM-Threads läuft er **single-threaded** (Korrektheit unberührt, nur Durchsatz).
- **Retention/Eviction läuft im WASM-Pfad nicht** — der Adapter triggert kein Thinning; ein Create/Write bleibt bis zum Snapshot vollständig im RAM.
- Zufall (GCM-Nonces, Argon2id-Salt) über `getrandom` (js-Backend).

**Positionierung:** derselbe Substrat-Kern trägt kernel-native Performance (Treiber), einen portablen FUSE-Pfad **und** einen modulfreien Browser-Pfad — mit einem einzigen On-Disk-Format über alle drei.

---

*Lizenz-Erwartung (Zero-Familie): Spec unter CC-BY-SA 4.0, Referenz-Implementierung unter Apache-2.0 OR MIT, Trademark-Schutz für die Zero-FS-Bezeichnung.*
