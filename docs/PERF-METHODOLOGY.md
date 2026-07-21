# sfs — Perf-Mess- und Aufbereitungs-Protokoll

**Zweck:** verhindern, dass Perf-Zahlen geraten, fehlgerahmt oder als unlesbare
Zahlenwand präsentiert werden. Diese Session hat gezeigt: ohne Protokoll rate ich
mich durch die Zahlen (falsch: „serieller Seal ist die Ursache", „17× Write-Verlust
pauschal", „1180× auch auf Partition"). Jede Perf-Aussage folgt ab jetzt diesem
Dokument. Es gilt für mich UND für jeden Perf-Agenten.

---

## 0. Kardinalregel

**Erst die Phase messen, dann die Ursache benennen — nie umgekehrt.** Keine
Attribution eines Flaschenhalses ohne Profiling, das ihn zeigt. „Es liegt
wahrscheinlich an X" ist verboten, bis X gemessen ist. Wenn eine Messung nicht
eindeutig ist: sagen „nicht eindeutig, nächster Messschritt Y" — NICHT mit einer
Vermutung füllen.

---

## 1. Jede Zahl trägt ihre vollständige Koordinate

Eine nackte MB/s-Zahl ist bedeutungslos und die Quelle meiner Fehlrahmungen. Jede
Messung wird auf diesen Achsen verortet, ALLE explizit:

| Achse | Werte | Falle (real passiert) |
|---|---|---|
| **Mode** | Engine (Rust direkt) · FUSE (sfs-mount) · DKMS (sfs.ko) · SaaS | Engine 833 MB/s ≠ Kernel 58 MB/s — nie vermischen |
| **Backend** | wachsendes File · **fixes Device/Partition** | grow_for-O(n²) bittet NUR das File; Partition war immer fein |
| **Cipher** | none · xts · gcm | NONE isoliert die Krypto-Kosten (war der Beweis: Krypto ist NICHT der Flaschenhals) |
| **Größe** | 4k/64k/1M/16M/256M/1G/4G | 4k+fsync = fsync-gebunden (Parität); Groß-Seq = Durchsatz (Verlust) — verschiedene Bottlenecks |
| **Pattern** | seq/rand × read/write | |
| **Sync-Policy** | buffered · fsync-pro-Op (`--end_fsync`/`O_SYNC`) · O_DIRECT | 4k+fsync ≠ buffered-seq — der ganze „17×" war der buffered-Fall |
| **Cache** | cold (umount/remount + drop_caches) · warm | `drop_caches` flusht NICHT sfs' in-Kernel-Caches → Read-Varianz |
| **Threads/QD** | psync iodepth 1 (kanonische Single-Thread-Zahl) · io_uring 1/8/32 (separate Skalierungsachse) | Ein historischer fio/io_uring-Crash wurde 2026-07-18 als behoben gemeldet; bis der externe Regression-Gate erneut grün ist, bleibt psync die veröffentlichte Vergleichsachse. Nie psync gegen io_uring als Gleiches-gegen-Gleiches rechnen. |

**Regel:** wenn ich eine Zahl nenne, nenne ich mode+backend+cipher+size+sync+cache.
Sonst ist es keine Messung, es ist ein Gefühl.

---

## 2. Apples-to-apples: der exakte Partner pro (Mode, Cipher)

Immer gegen den Partner, der DASSELBE tut — nicht gegen „die Welt".

| Mode | unverschlüsselt | verschlüsselt |
|---|---|---|
| **DKMS** (sfs.ko) | ext4, fat32 (bare Partition, Kernel) | ext4-auf-LUKS2 (aes-xts-plain64, beide AES-XTS/AES-NI); sfs-gcm standalone (authentifiziert, kein dm-crypt-Äquiv.) |
| **FUSE** (sfs-mount) | fuse2fs (ext4-über-FUSE), bindfs/passthrough (FUSE-Overhead-Boden) | gocryptfs (FUSE-AES) |
| **SaaS** | — (kein FS-Partner; ehrlich gegen die Roh-Disk-Decke + At-Rest None-vs-AEAD) | — |

Gleiche Hardware, gleiche Partition/Backing, gleiche fio-Job-Zeile (bis auf den zu
variierenden Parameter), gleiche cold-cache-Methode. Cross-Cipher/Cross-Mode nur mit
explizitem Label „nicht apples-to-apples".

---

## 3. Projekt-spezifische Fallen (Checkliste vor jeder Kampagne)

- [ ] **sfs kann kein O_DIRECT** → device-truth-Spalte nur für ext4/LUKS; sfs nur buffered. Sagen.
- [ ] **io_uring separat behandeln** → 2026-07-18 als behoben gemeldet, aber vor
      Veröffentlichung extern revalidieren; die kanonische faire Matrix bleibt
      fio psync single-thread auf beiden Seiten.
- [ ] **`drop_caches` flusht sfs-Kernel-Caches nicht** → cold = umount/remount + drop_caches; Read-Varianz benennen.
- [ ] **buffered vs fsync-pro-Op** — welcher misst was ich behaupte? 4k+fsync ist der durability-Fall.
- [ ] **File vs Partition** — welches Deployment? Zahl labeln. Raw-Partition =
      nativer v12-Kernelpfad; Container-File auf ext4 = portabler FUSE-Pfad.
- [ ] **Engine vs Kernel** — Rust-Engine-Bench ≠ .ko-Bench. Nie mischen.
- [ ] **GCM = 2× Slot-Layout** (fragsize+16 → +1 Block) → mehr I/O als XTS, unabhängig von der CPU.
- [ ] **Derivierte fragsize pro Größe** (D-2b) — 256M-File hat andere Fragmente als 1M; bei Multi-GiB protokollieren.
- [ ] **Sustained sfs-randwrite** braucht mitlaufende `sfsctl evict`+`trim` (Steady-State), sonst ENOSPC.
- [ ] **FUSE Large-I/O/Unmount-Regression** → die frühere ≥256-MiB-Hang- und
      Daemon-Leak-Grenze gilt als behoben. Trotzdem pro Lauf Timeout,
      Session-Ende, OOM/dmesg, Leak-Zahl und freien RAM prüfen; nie wieder durch
      eine feste Größenkappe unsichtbar machen.

---

## 4. Ursachen-Attribution nur per Dekomposition

Wenn ein Deficit gefunden wird, wird es zerlegt, bevor eine Ursache genannt wird:
- **CPU-Phasen** (seal, encode): per-Phase-Timer (feature-gated `commit_profile`) oder `perf`/Flamegraph. Frage: seriell (1 Kern) oder parallel (N)?
- **I/O-Phasen** (fsync, flush): `strace -c -f` / `blktrace` — Anzahl UND Latenz der Flushes/Commits zählen.
- **Amplification**: physische Bytes / logische Bytes messen (Counter `PHYS_BYTES`/`FLUSHES`/`NODE_PAIRS`). Ein 4k-Write der 2,9 MB schreibt = 716× — DAS ist die Zahl, die den Bug findet.
- Ergebnis: gerankte Phasen-Tabelle (Phase → ms → % → 1-Kern-oder-N), dann die Ursache. Nie vorher.

Gegenprobe-Isolation: NONE misst „ohne Krypto"; roher Seal-Bench misst „nur Krypto".
Wenn NONE ≈ XTS → Krypto ist es nicht (so wurde meine Seal-Vermutung widerlegt).

---

## 5. Aufbereitung: wie Ergebnisse präsentiert werden (KEINE Zahlenwand)

Sandra hat es zweimal gesagt: eine Wand aus Zahlen als Text ist unlesbar. Standard:

- **Eine kleine Tabelle pro Vergleich** (Mode), max ~6 Zeilen sichtbar. Spalten:
  `Workload | sfs | Partner | Verhältnis | Verdikt`.
- **Verdikt-Spalte Pflicht:** WIN / LOSS / PAR gegen das „≥ ext4/fat32"-Ziel. Ein
  17×-Verlust ist LOSS, nicht „~on par". Kein Weichspülen.
- **Eine Kernaussage pro Tabelle** in Prosa darüber — was der Leser mitnimmt.
- **Absolutwert UND Verhältnis** (nicht nur eins). Bei CPU-Phasen: 1-Kern-oder-N.
- **Rauschen markieren** (>10% Spread → `*` + Vorsicht). **Cache-bound vs device-truth**
  trennen. **Nicht messbare Achsen** als Lücke benennen, nicht kaschieren.
- **Für komplexe Ergebnisse: ein Artifact** (visuelle HTML-Tabelle) statt Text-Wall.
- **Ehrlichkeits-Regeln:** nicht schmeichelhaft runden; Verlust ≠ Parität; „gemessen"
  strikt von „vermutet" trennen; Caveat inline, nicht in einer Fußnote versteckt;
  wenn sfs verliert, um wie viel und warum — als Zahl, nicht als Adjektiv.

---

## 6. Reproduzierbarkeit (jede Zahl rückverfolgbar)

- Eingecheckt sind die allgemeinen Treiber (`scripts/bench/vm-kernel.sh`,
  `scripts/bench/vm-staggered.sh`) und Summary-Generatoren. Der aktuelle
  Ergebnisstand liegt in
  [`perf/perf-report-2026-07-20.html`](perf/perf-report-2026-07-20.html):
  **N=10 gültige/fault-freie Läufe pro Zelle, arithmetisches Mittel**. Die
  HTML-Datei enthält Aggregate, nicht die zehn Einzelwerte.
- Für jede veröffentlichte Kampagne müssen Runner-Version, unveränderte
  per-run-Rohdaten und Health-Nachweise zusammen archiviert werden. Dazu gehören
  Source-Commit, Hash der tatsächlich gestarteten Module/Binaries, `uname -r`,
  CPU-AES-Flag, fio-Version, mkfs/cryptsetup-Parameter, Cold-Cache-Methode und
  abgeleitete fragsize. Ein kurzer Artefakt-Hash ohne Zuordnung zum Source-Commit
  reicht nicht.
- Explorative Kampagnen: mindestens 3 Wiederholungen, Median und Spread. Finale
  Headline-Kampagne: das im Report deklarierte N und Aggregat verwenden; nie
  Median und Mittelwert zwischen Text, Generator und HTML vermischen.
- Rohdaten vergangener Kampagnen nur dann als reproduzierbar bezeichnen, wenn
  sie tatsächlich in git, einem Release-Artefakt oder einem unveränderlichen
  externen Archiv vorhanden sind. „Aus der Historie ziehbar“ ist kein Ersatz
  für einen nachgewiesenen Pfad.
- Silizium-Decke als Sanity: kein buffered-Wert > O_DIRECT-Ceiling ohne „= Cache"-Label.

---

## 7. Checkliste, die ich vor JEDER Perf-Aussage durchgehe

1. Trägt jede Zahl ihre volle Koordinate (Mode/Backend/Cipher/Size/Sync/Cache)?
2. Exakter Partner, identische Bedingungen?
3. Ist die Ursache gemessen (Dekomposition) oder geraten? Wenn geraten → nicht sagen.
4. Verdikt WIN/LOSS/PAR ehrlich (kein 17× als „on par")?
5. Lesbar (kleine Tabelle + eine Kernaussage), kein Zahlen-Wall?
6. Reproduzierbar (exakter Runner + per-run-Rohdaten/Health + Source-Commit +
   gestartete Artefakt-Hashes)?
7. Caveats inline (O_DIRECT/io_uring/cache/file-vs-partition/engine-vs-kernel)?

Wenn eine Antwort „nein" ist: die Aussage ist noch nicht fertig.
