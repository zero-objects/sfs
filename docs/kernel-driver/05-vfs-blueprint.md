# [HISTORISCH] Auftrag 5 — VFS-Blaupause des read-only-MVP

> **Archäologie, kein aktueller Funktionsumfang.** Der Branch enthält inzwischen
> einen read/write-Treiber. Maßgeblich sind `kernel/sfs_*.c`, `kernel/sfs_fs.h`,
> das Kbuild/DKMS-Setup und die externe Kernel-Release-Checkliste; die folgenden
> read-only-Entscheidungen dokumentieren lediglich den Ausgangspunkt.

**Zielplattform:** Linux **v6.12** (Debian 13 „trixie", Kernel 6.12.x), out-of-tree-Modul via DKMS.
**Muster-Dateisysteme:** squashfs (primär — Block-Dekompression ≈ unsere Fragment-Entschlüsselung), erofs, romfs.
**Verifikationsstand:** Alle Kernel-Signaturen/Zeilennummern wurden gegen den Tag `v6.12` des Mainline-Trees
(raw.githubusercontent.com/torvalds/linux/v6.12/…) geprüft (Abruf 2026-07-07). Zitate der Form
`v6.12 fs/super.c:1655` beziehen sich auf diesen Tag. sfs-Zitate beziehen sich auf den lokalen Stand
(git master, Commit 48fc248).

> **Konvention in diesem Dokument:** `SFS_BLOCK_SIZE = 4096` (Container-Logikblock),
> Fragmentgröße = `2^fragsize_exp` Bytes, Minimum `2^12` = 4 KiB
> (`FRAGSIZE_FLOOR_EXP = 12`, sfs `crates/sfs-core/src/block.rs:54`), typisch 128 KiB (`2^17`).
> Byte-Layout des Containers ist NICHT Gegenstand dieses Dokuments (siehe Aufträge 1–4);
> hier geht es um die Kernel-Seite: VFS-Verdrahtung, Read-Pfad, Crypto-API, Build.

---

## 0. Gesamtarchitektur des Moduls

```
sfs.ko
├── super.c    — file_system_type, fs_context, fill_super, super_operations
├── inode.c    — sfs_iget (iget5_locked, Key = 16-Byte-UUID), inode_operations
├── dir.c      — sfs_lookup, sfs_readdir (dir_emit)
├── data.c     — address_space_operations: read_folio + readahead (Fragment-Entschlüsselung)
├── symlink.c  — get_link (entschlüsseltes Ziel in i_link)
├── crypto.c   — HKDF-SHA256 über hmac(sha256), gcm(aes)-Decrypt, xts(aes)-Decrypt
└── sfs_fs.h   — On-Disk-Strukturen (aus Aufträgen 1–4), Superblock-Info-Structs
```

Alles synchron, kein Workqueue-/Async-Bedarf: der Read-Pfad läuft im Prozesskontext
(`read_folio`/`readahead` dürfen schlafen), Crypto wird sync alloziert (§5).

---

## 1. Mount-API: fs_context + get_tree_bdev

### 1.1 file_system_type und Registrierung

```c
static struct file_system_type sfs_fs_type = {
    .owner           = THIS_MODULE,
    .name            = "sfs",
    .init_fs_context = sfs_init_fs_context,
    .parameters      = sfs_fs_parameters,
    .kill_sb         = kill_block_super,     /* v6.12 fs/super.c:1706, EXPORT_SYMBOL :1717 */
    .fs_flags        = FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("sfs");

static int __init sfs_init(void)
{
    int err = sfs_init_inode_cache();        /* kmem_cache, §2.2 */
    if (err) return err;
    err = register_filesystem(&sfs_fs_type);
    if (err) sfs_destroy_inode_cache();
    return err;
}

static void __exit sfs_exit(void)
{
    unregister_filesystem(&sfs_fs_type);
    /* rcu_barrier() VOR Cache-Destroy — free_inode läuft via RCU (§2.2) */
    rcu_barrier();
    sfs_destroy_inode_cache();
}
module_init(sfs_init);
module_exit(sfs_exit);
```

`FS_REQUIRES_DEV` ⇒ Quelle muss ein Blockdevice sein. Container-Dateien werden
via Loop-Device gemountet; `mount -t sfs -o loop /pfad/container /mnt` erledigt
`losetup` automatisch (util-linux), der Kernel sieht nur `/dev/loopN`.
Loop-Devices haben default `logical_block_size = 512` — kompatibel mit
`sb_min_blocksize(sb, 4096)` (§1.4).

### 1.2 fs_context_operations (v6.12 include/linux/fs_context.h:115–122)

Exakte Struktur in 6.12:

```c
struct fs_context_operations {
    void (*free)(struct fs_context *fc);
    int (*dup)(struct fs_context *fc, struct fs_context *src_fc);
    int (*parse_param)(struct fs_context *fc, struct fs_parameter *param);
    int (*parse_monolithic)(struct fs_context *fc, void *data);
    int (*get_tree)(struct fs_context *fc);
    int (*reconfigure)(struct fs_context *fc);
};
```

Muster (analog squashfs, `v6.12 fs/squashfs/super.c:507–512, 540`):

```c
struct sfs_mount_opts {
    /* z. B. Schlüsselreferenz: key_id (Kernel-Keyring-Serial) oder keyfile-Deskriptor */
    key_serial_t key_id;
};

enum sfs_param { Opt_key_id };

static const struct fs_parameter_spec sfs_fs_parameters[] = {
    fsparam_s32("key_id", Opt_key_id),
    {}
};

static int sfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct sfs_mount_opts *opts = fc->fs_private;
    struct fs_parse_result result;
    int opt = fs_parse(fc, sfs_fs_parameters, param, &result);
    if (opt < 0)
        return opt;
    switch (opt) {
    case Opt_key_id: opts->key_id = result.int_32; break;
    default: return -EINVAL;
    }
    return 0;
}

static int sfs_get_tree(struct fs_context *fc)
{
    return get_tree_bdev(fc, sfs_fill_super);
}

static int sfs_reconfigure(struct fs_context *fc)
{
    sync_filesystem(fc->root->d_sb);
    fc->sb_flags |= SB_RDONLY;    /* rw-Remount stillschweigend auf ro zwingen —
                                     exakt das squashfs-Muster, v6.12 fs/squashfs/super.c:488–500 */
    return 0;
}

static void sfs_free_fs_context(struct fs_context *fc)
{
    kfree(fc->fs_private);
}

static const struct fs_context_operations sfs_context_ops = {
    .get_tree    = sfs_get_tree,
    .free        = sfs_free_fs_context,
    .parse_param = sfs_parse_param,
    .reconfigure = sfs_reconfigure,
};

static int sfs_init_fs_context(struct fs_context *fc)
{
    struct sfs_mount_opts *opts = kzalloc(sizeof(*opts), GFP_KERNEL);
    if (!opts)
        return -ENOMEM;
    fc->fs_private = opts;
    fc->ops = &sfs_context_ops;
    fc->sb_flags |= SB_RDONLY;    /* read-only erzwingen, bevor das bdev geöffnet wird —
                                     setup_bdev_super öffnet dann BLK_OPEN_READ-only */
    return 0;
}
```

**Wichtig:** `fc->sb_flags |= SB_RDONLY` bereits in `init_fs_context` setzen, damit
`setup_bdev_super()` das Blockdevice ohne Schreibmodus öffnet und ein rw-Mount desselben
Devices durch andere nicht blockiert wird.

### 1.3 get_tree_bdev — Signatur und Ablauf (v6.12)

```c
/* v6.12 fs/super.c:1655–1660, EXPORT_SYMBOL (nicht GPL-only) :1661 */
int get_tree_bdev(struct fs_context *fc,
                  int (*fill_super)(struct super_block *, struct fs_context *));
```

Interner Ablauf (`get_tree_bdev_flags`, `v6.12 fs/super.c:1604–1650`):

1. `fc->source` fehlt → `invalf(fc, "No source specified")` (= -EINVAL an Userspace).
2. `lookup_bdev(fc->source, &dev)` — löst Pfad zu `dev_t` auf (Fehler: -ENOENT/-ENOTBLK).
3. `fc->sb_flags |= SB_NOSEC` (Zeile 1621 — automatisch, nichts zu tun).
4. `sget_dev(fc, dev)` — findet existierenden oder alloziert neuen `super_block`.
5. Existiert `s->s_root` bereits (re-Mount desselben Devices): RO/RW-Wechsel → -EBUSY.
6. Neu: `setup_bdev_super(s, fc->sb_flags, fc)` — öffnet das bdev, setzt
   `s->s_bdev_file`, `s->s_bdev`, `s->s_dev`, initiale `s_blocksize`.
7. Ruft unser `fill_super(s, fc)`. Fehler ⇒ `deactivate_locked_super(s)` (unser
   `put_super`/Teardown muss partiellen Zustand vertragen!).
8. Erfolg: `s->s_flags |= SB_ACTIVE`, `fc->root = dget(s->s_root)`.

### 1.4 fill_super — Ablauf und Blockgrößen

**Signatur (von get_tree_bdev vorgegeben):**
`static int sfs_fill_super(struct super_block *sb, struct fs_context *fc)`

```c
static int sfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct sfs_mount_opts *opts = fc->fs_private;
    struct sfs_sb_info *sbi;
    struct buffer_head *bh;
    struct inode *root;

    sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
    if (!sbi)
        return -ENOMEM;
    sb->s_fs_info = sbi;

    /*
     * Geräte-Blockgröße setzen. v6.12 block/bdev.c:193–201:
     *   sb_min_blocksize(sb, size) = max(size, bdev_logical_block_size) → sb_set_blocksize.
     * sb_set_blocksize (block/bdev.c:180–191) → set_blocksize(sb->s_bdev_file, size).
     * set_blocksize (block/bdev.c:153–178) verlangt:
     *   - Zweierpotenz, 512 <= size <= PAGE_SIZE
     *   - size >= bdev_logical_block_size(bdev)
     * Rückgabe von sb_min_blocksize: die gesetzte Blockgröße, 0 bei Fehler.
     */
    if (sb_min_blocksize(sb, SFS_BLOCK_SIZE) != SFS_BLOCK_SIZE) {
        errorf(fc, "sfs: unable to set blocksize %u", SFS_BLOCK_SIZE);
        return -EINVAL;   /* z. B. Device mit logical_block_size > 4096 */
    }

    /* Superblock-Block lesen: sb_bread liefert s_blocksize (=4096) Bytes.
       v6.12 include/linux/buffer_head.h:344–347:
       sb_bread(sb, block) = __bread_gfp(sb->s_bdev, block, sb->s_blocksize, __GFP_MOVABLE) */
    bh = sb_bread(sb, SFS_SUPERBLOCK_BLOCK /* Blockindex, nicht Byteoffset! */);
    if (!bh) {
        errorf(fc, "sfs: unable to read superblock");
        return -EIO;
    }

    /* Magic/Version/Feature-Flags prüfen (Byte-Layout: Auftrag 1).
       Unbekannte incompat-Features → -EINVAL. Falsches Magic → -EINVAL. */
    if (sfs_parse_superblock(sbi, bh->b_data) != 0) {
        brelse(bh);
        errorf(fc, "sfs: bad magic or unsupported feature");
        return -EINVAL;
    }
    brelse(bh);

    /* Schlüsselmaterial beziehen (Kernel-Keyring über opts->key_id) und
       Crypto-Handles allozieren (§5.1). Fehler: -ENOKEY / -ENOMEM / -ENOENT
       (Algorithmus nicht verfügbar). */
    if (sfs_crypto_init(sbi, opts) != 0)
        return -ENOKEY;

    sb->s_magic          = SFS_SUPER_MAGIC;      /* eigener 32-bit-Wert, Auftrag 1 */
    sb->s_flags         |= SB_RDONLY | SB_NOATIME;
    sb->s_maxbytes       = MAX_LFS_FILESIZE;
    sb->s_time_gran      = 1;                    /* ns-Auflösung, falls Format ns speichert */
    sb->s_op             = &sfs_super_ops;
    sb->s_xattr          = NULL;                 /* v1: keine xattrs */
    sb->s_export_op      = NULL;                 /* v1: kein NFS-Export */
    uuid_copy(&sb->s_uuid, &sbi->container_uuid);

    root = sfs_iget(sb, sbi->root_uuid);         /* §2.1 */
    if (IS_ERR(root))
        return PTR_ERR(root);

    sb->s_root = d_make_root(root);              /* konsumiert root auch im Fehlerfall */
    if (!sb->s_root)
        return -ENOMEM;
    return 0;
}
```

**Fehlerpfad-Regel:** `fill_super`-Fehler führt zu `deactivate_locked_super` → unser
`kill_sb = kill_block_super` läuft NICHT für den Teardown des halbinitialisierten sb;
stattdessen läuft `sb->s_op->put_super` nur wenn `s_root` gesetzt war. Daher:
`sfs_put_super` UND ein defensiver Teardown, der `sb->s_fs_info == NULL` bzw. teilweise
NULL-Handles toleriert. Praxis-Muster (squashfs `v6.12 fs/squashfs/super.c:180 ff.`):
alles über `s_fs_info` erreichbar machen und in `put_super` bedingungslos, aber
NULL-tolerant freigeben.

```c
static void sfs_put_super(struct super_block *sb)
{
    struct sfs_sb_info *sbi = sb->s_fs_info;
    if (!sbi)
        return;
    sfs_crypto_destroy(sbi);          /* crypto_free_aead/…, NULL-tolerant */
    kfree(sbi->catalog_cache);        /* etc. */
    kfree(sbi);
    sb->s_fs_info = NULL;
}

static const struct super_operations sfs_super_ops = {
    .alloc_inode   = sfs_alloc_inode,     /* §2.2 */
    .free_inode    = sfs_free_inode,
    .put_super     = sfs_put_super,
    .statfs        = sfs_statfs,          /* f_type = SFS_SUPER_MAGIC, f_bsize = fragsize o. 4096 */
    .drop_inode    = generic_delete_inode /* ro-FS: Inodes nicht cachen? Nein — s.u. */
};
```

**Hinweis `drop_inode`:** Für ein ro-FS ist das Standardverhalten (Inode im Cache halten,
`drop_inode = NULL` ⇒ `generic_drop_inode`) richtig; `generic_delete_inode` würde das
Caching abschalten. Empfehlung: **Feld weglassen** (NULL). squashfs setzt es auch nicht.

### 1.5 4-KiB-Blöcke lesen: sb_bread vs. bdev-Pagecache

- `sb_bread(sb, block)` liefert einen `buffer_head` mit genau `sb->s_blocksize` Bytes
  (v6.12 include/linux/buffer_head.h:344–347). Nach `sb_min_blocksize(sb, 4096)` ist
  ein „Block" exakt unser 4-KiB-Containerblock; `bh->b_data` zeigt in den
  bdev-Pagecache. Freigabe mit `brelse(bh)`.
- Ein 128-KiB-Fragment (+16 Byte GCM-Tag, §5) besteht aus 32 (+1) 4-KiB-Blöcken
  → Leseschleife über `sb_bread`. Für die Crypto-API können die bh-Seiten direkt als
  Scatterlist verwendet werden (Zero-Copy, §5.4) oder in einen kmalloc-Puffer kopiert
  werden (v1, einfacher).
- `sb_bread` ist gepuffert und blockierend; völlig ausreichend (squashfs macht exakt das,
  `squashfs_bio_read`-Pfad ist erst eine spätere Optimierung).
- **Nicht** `sb_bread` mit Byteoffsets füttern: Argument ist der **Blockindex**
  (`sector_t block`), Byteoffset = `block << sb->s_blocksize_bits`.

---

## 2. Inode-Modell

### 2.1 iget5_locked mit UUID als Schlüssel

sfs adressiert Objekte über 16-Byte-UUIDs (`crates/sfs-core/src/crypto/mod.rs:126`),
nicht über kleine Inodennummern. Deshalb `iget5_locked` statt `iget_locked`:

```c
/* v6.12 fs/inode.c:1328–1330 (EXPORT_SYMBOL) */
struct inode *iget5_locked(struct super_block *sb, unsigned long hashval,
                           int (*test)(struct inode *, void *),
                           int (*set)(struct inode *, void *), void *data);
```

```c
struct sfs_inode_info {
    u8              uuid[16];
    /* + Fragment-Mapping-Infos, fragsize_exp, last_frag_length, version, … (Aufträge 2–4) */
    struct inode    vfs_inode;
};
static inline struct sfs_inode_info *SFS_I(struct inode *inode)
{
    return container_of(inode, struct sfs_inode_info, vfs_inode);
}

static int sfs_inode_test(struct inode *inode, void *data)
{
    return memcmp(SFS_I(inode)->uuid, data, 16) == 0;
}

static int sfs_inode_set(struct inode *inode, void *data)
{
    memcpy(SFS_I(inode)->uuid, data, 16);
    /* i_ino ist nur informativ (stat.st_ino, dir_emit): stabile 64-bit-Ableitung.
       Empfehlung: die ersten 8 UUID-Bytes little-endian. Kollisionsgefahr in i_ino
       ist unkritisch, weil die Hash-Identität über test() (voller 16-Byte-Vergleich)
       läuft — i_ino ist NICHT der Cache-Schlüssel. */
    inode->i_ino = get_unaligned_le64(data);
    return 0;
}

struct inode *sfs_iget(struct super_block *sb, const u8 uuid[16])
{
    /* hashval: 64/32-bit Streuwert über die UUID; xxh64 ist im Kernel verfügbar
       (include/linux/xxhash.h), alternativ full_name_hash(NULL, uuid, 16). */
    unsigned long hashval = (unsigned long)xxh64(uuid, 16, 0);
    struct inode *inode = iget5_locked(sb, hashval, sfs_inode_test,
                                       sfs_inode_set, (void *)uuid);
    int err;

    if (!inode)
        return ERR_PTR(-ENOMEM);
    if (!(inode->i_state & I_NEW))
        return inode;                      /* Cache-Hit, fertig initialisiert */

    err = sfs_read_inode(inode);           /* Katalog-Record lesen+entschlüsseln,
                                              Felder füllen (unten) */
    if (err) {
        iget_failed(inode);                /* Pflicht bei I_NEW-Fehler! */
        return ERR_PTR(err);
    }
    unlock_new_inode(inode);               /* Pflicht bei I_NEW-Erfolg! */
    return inode;
}
```

**Feldbefüllung in `sfs_read_inode`** (Zeitsetter sind in 6.12 die
`inode_set_{a,m,c}time`-Familie; direkter Feldzugriff auf `i_atime` existiert nicht mehr):

```c
inode->i_mode = mode;                       /* S_IFREG|0444 etc. aus Katalog-Record */
i_uid_write(inode, uid); i_gid_write(inode, gid);
set_nlink(inode, nlink);                    /* Verzeichnisse: 2 + Unterverzeichnisse */
inode->i_size = size;                       /* logische Dateigröße in Bytes */
inode->i_blocks = (size + 511) >> 9;        /* 512-Byte-Einheiten für stat */
inode_set_mtime(inode, sec, nsec);
inode_set_atime_to_ts(inode, inode_get_mtime(inode));
inode_set_ctime_to_ts(inode, inode_get_mtime(inode));

switch (mode & S_IFMT) {
case S_IFREG:
    inode->i_op  = &sfs_file_inode_ops;     /* leer bis auf .getattr optional */
    inode->i_fop = &generic_ro_fops;        /* §3.1 */
    inode->i_mapping->a_ops = &sfs_aops;    /* §3 */
    break;
case S_IFDIR:
    inode->i_op  = &sfs_dir_inode_ops;      /* .lookup = sfs_lookup */
    inode->i_fop = &sfs_dir_ops;            /* §4 */
    break;
case S_IFLNK:
    err = sfs_load_symlink(inode);          /* §2.4 */
    break;
default:
    /* Gerätedateien/FIFOs falls das Format sie kennt: */
    init_special_inode(inode, mode, rdev);
    break;
}
```

### 2.2 alloc_inode / free_inode mit kmem_cache

```c
static struct kmem_cache *sfs_inode_cachep;

static struct inode *sfs_alloc_inode(struct super_block *sb)
{
    struct sfs_inode_info *si =
        alloc_inode_sb(sb, sfs_inode_cachep, GFP_KERNEL);  /* 6.12: alloc_inode_sb, NICHT
                                                              kmem_cache_alloc direkt! */
    if (!si)
        return NULL;
    return &si->vfs_inode;
}

static void sfs_free_inode(struct inode *inode)
{
    kfree(SFS_I(inode)->symlink_target);   /* falls §2.4 Variante A */
    kmem_cache_free(sfs_inode_cachep, SFS_I(inode));
}

static void sfs_inode_init_once(void *p)
{
    struct sfs_inode_info *si = p;
    inode_init_once(&si->vfs_inode);
}

int __init sfs_init_inode_cache(void)
{
    sfs_inode_cachep = kmem_cache_create("sfs_inode_cache",
        sizeof(struct sfs_inode_info), 0,
        SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT, sfs_inode_init_once);
    return sfs_inode_cachep ? 0 : -ENOMEM;
}
```

Pflichten: `alloc_inode_sb()` (Memcg-korrekt, seit 5.18 Standard), `inode_init_once`
als Cache-Konstruktor, `rcu_barrier()` vor `kmem_cache_destroy` im Modul-Exit
(`free_inode` wird via RCU aufgerufen).

### 2.3 lookup

```c
static struct dentry *sfs_lookup(struct inode *dir, struct dentry *dentry,
                                 unsigned int flags)
{
    struct inode *inode = NULL;
    u8 uuid[16];
    int err;

    if (dentry->d_name.len > SFS_NAME_MAX)
        return ERR_PTR(-ENAMETOOLONG);

    err = sfs_dir_find(dir, &dentry->d_name, uuid);  /* Verzeichnis-Records
                                                        entschlüsseln + Namen suchen */
    if (err == 0)
        inode = sfs_iget(dir->i_sb, uuid);           /* kann ERR_PTR sein */
    else if (err != -ENOENT)
        return ERR_PTR(err);                          /* I/O-/Integritätsfehler */

    return d_splice_alias(inode, dentry);  /* behandelt NULL (=negatives dentry)
                                              und ERR_PTR korrekt */
}
```

`d_splice_alias` statt `d_add`: kanonisch seit Jahren, korrekt für alle Fälle inkl.
ERR_PTR-Durchreichung.

### 2.4 Symlinks: simple_get_link vs. page_get_link

v6.12-Signatur: `const char *(*get_link)(struct dentry *, struct inode *, struct delayed_call *)`
(v6.12 include/linux/fs.h:2129).

**Variante A (EMPFOHLEN): entschlüsseltes Ziel in `i_link`, `simple_get_link`.**
`simple_get_link` gibt schlicht `inode->i_link` zurück (v6.12 fs/libfs.c:1694–1699,
fertige ops: `simple_symlink_inode_operations`, libfs.c:1701).

```c
static int sfs_load_symlink(struct inode *inode)
{
    struct sfs_inode_info *si = SFS_I(inode);
    if (inode->i_size == 0 || inode->i_size > SFS_SYMLINK_MAX /* z. B. 4095 */)
        return -EUCLEAN;                     /* korruptes Format */
    si->symlink_target = kmalloc(inode->i_size + 1, GFP_KERNEL);
    if (!si->symlink_target)
        return -ENOMEM;
    int err = sfs_read_and_decrypt_object(inode, si->symlink_target, inode->i_size);
    if (err) { kfree(si->symlink_target); si->symlink_target = NULL; return err; }
    si->symlink_target[inode->i_size] = '\0';
    inode->i_link = si->symlink_target;
    inode->i_op = &simple_symlink_inode_operations;
    return 0;
}
```

Vorteile: kein Pagecache-Umweg, RCU-walk-fähig (`get_link` mit `dentry==NULL` funktioniert,
weil `i_link` bereits gesetzt ist), Ziel wird genau einmal entschlüsselt.
Freigabe in `free_inode` (§2.2). Kosten: kmalloc pro Symlink-Inode — bei ≤4 KiB egal.

**Variante B: `page_get_link`** (v6.12 fs/namei.c:5303–5328) liest Seite 0 des
Symlink-Mappings über unsere `a_ops->read_folio`. Dann zwingend
`inode_nohighmem(inode)` setzen — `page_get_link` hat `BUG_ON(mapping_gfp_mask &
__GFP_HIGHMEM)` (namei.c:5324). Nur sinnvoll, wenn Symlink-Ziele im selben
Fragment-Datenpfad liegen wie Dateiinhalte. Für sfs: unnötig komplex → Variante A.

---

## 3. Read-Pfad: read_folio/readahead (Empfehlung) vs. read_iter

### 3.1 Entscheidungsmatrix

| Kriterium | A: `a_ops.read_folio`+`readahead` + `generic_ro_fops` | B: eigene `f_op.read_iter` |
|---|---|---|
| `mmap` | gratis (`filemap_fault` über a_ops) | praktisch unmöglich ohne a_ops |
| Plaintext-Caching | Pagecache cached entschlüsselte Daten → jede Wiederholungslektüre ohne Krypto | jedes read() entschlüsselt neu |
| `sendfile`/`splice` | gratis (`filemap_splice_read`) | Handarbeit |
| Readahead-Heuristik | Kernel-Readahead ruft unser `readahead` mit ganzen Fenstern | selbst bauen |
| Komplexität | Fragment→Folios-Verteilung nötig | einfacher Einstieg, aber Sackgasse |
| Sicherheit | Plaintext liegt im Pagecache (RAM) | Plaintext nur transient |

**Empfehlung: Variante A.** Exakt das squashfs-Modell: 128-KiB-„Block" wird als Ganzes
dekomprimiert/entschlüsselt und auf die zugehörigen Seiten verteilt
(`v6.12 fs/squashfs/file.c:446` `squashfs_read_folio`; a_ops mit
`.read_folio`/`.readahead` file.c:663–665). `generic_ro_fops`
(v6.12 fs/read_write.c:28–35, EXPORT_SYMBOL) liefert
`.llseek=generic_file_llseek, .read_iter=generic_file_read_iter,
.mmap=generic_file_readonly_mmap, .splice_read=filemap_splice_read`.
Der Pagecache-Plaintext ist akzeptabel: dm-crypt/fscrypt cachen ebenfalls Klartext;
wer das nicht will, braucht ohnehin RAM-Verschlüsselung.

v6.12-Signaturen (include/linux/fs.h:399, 407):

```c
int  (*read_folio)(struct file *, struct folio *);
void (*readahead)(struct readahead_control *);
```

### 3.2 Geometrie

```
frag_bytes    = 1 << fragsize_exp            /* typ. 131072 */
pages_per_frag= frag_bytes >> PAGE_SHIFT     /* 32 bei 4-KiB-Seiten */
frag_index(folio) = folio->index >> (fragsize_exp - PAGE_SHIFT)
frag_len(i)   = (i == last_frag) ? last_frag_length : frag_bytes
                /* last_frag_length aus Katalog (sfs crates/sfs-core/src/block.rs:146–176,
                   Auftrag 2 für On-Disk-Encoding); XTS-Suite: gespeicherte Länge kann
                   < physischer (auf 16 gepaddeter) Länge sein — Klartext trunkieren!
                   (sfs crates/sfs-core/src/crypto/xts.rs:38–50) */
ct_len(i)     = frag_len_phys(i) + 16        /* GCM: +16 Tag; XTS: +0 */
```

Keine Large-Folio-Unterstützung aktivieren (kein `mapping_set_large_folios`);
dann liefert der Kernel order-0-Folios. Trotzdem defensiv `folio_size(folio)` benutzen.

### 3.3 read_folio — Pseudocode

Kernidee: pro Aufruf das ganze 128-KiB-Fragment entschlüsseln und ALLE
zugehörigen Seiten füllen (nicht nur die angefragte), sonst wird jedes Fragment bis zu
32-mal entschlüsselt. Für die Geschwister-Seiten `grab_cache_folio_nowait`-Muster; wer
v1 einfach halten will, füllt nur das angefragte Folio und verlässt sich auf §3.4
`readahead` für den Massenpfad plus einen kleinen Fragment-Plaintext-Cache (ein Eintrag
pro Mount, mutex-geschützt: `(inode, frag_idx, plaintext[frag_bytes])`) — das ist das
squashfs-„fragment cache"-Muster in minimal.

```c
static int sfs_read_folio(struct file *file, struct folio *folio)
{
    struct inode *inode = folio->mapping->host;
    struct sfs_sb_info *sbi = inode->i_sb->s_fs_info;
    u64 frag = folio->index >> (sbi->fragsize_exp - PAGE_SHIFT);
    loff_t isize = i_size_read(inode);
    int err = 0;

    if ((loff_t)folio->index << PAGE_SHIFT >= isize) {
        folio_zero_range(folio, 0, folio_size(folio));   /* Loch hinter EOF */
        folio_mark_uptodate(folio);
        goto out_unlock;
    }

    /* 1. Fragment-Plaintext besorgen (Cache-Hit oder Lesen+Entschlüsseln) */
    struct sfs_frag_buf *pb = sfs_get_fragment(inode, frag);  /* §3.5 + §5 */
    if (IS_ERR(pb)) { err = PTR_ERR(pb); goto out_unlock; }

    /* 2. Relevanten Ausschnitt in dieses Folio kopieren, Rest nullen */
    size_t off_in_frag = (folio->index << PAGE_SHIFT) & (sbi->frag_bytes - 1);
    size_t avail = min_t(size_t, pb->plain_len - off_in_frag, folio_size(folio));
    memcpy_to_folio(folio, 0, pb->plain + off_in_frag, avail);
    if (avail < folio_size(folio))
        folio_zero_range(folio, avail, folio_size(folio) - avail);
    folio_mark_uptodate(folio);
    sfs_put_fragment(pb);

out_unlock:
    folio_unlock(folio);
    return err;   /* err != 0 && !uptodate ⇒ Leser bekommt -EIO */
}
```

**Fehlerkontrakt:** Bei Fehler das Folio NICHT uptodate markieren, aber IMMER
`folio_unlock` aufrufen und den Fehler zurückgeben. GCM-Tag-Fehler (§5.2, -EBADMSG)
auf **-EIO** abbilden und `pr_err_ratelimited` loggen — Userspace soll I/O-Fehler
sehen, kein Crypto-Detail.

### 3.4 readahead — Pseudocode

```c
static void sfs_readahead(struct readahead_control *ractl)
{
    struct inode *inode = ractl->mapping->host;
    struct sfs_sb_info *sbi = inode->i_sb->s_fs_info;
    struct folio *folio;

    /* readahead_count(ractl) Folios ab readahead_pos(ractl).
       Strategie: fragmentweise arbeiten; pro berührtem Fragment einmal
       entschlüsseln, dann alle Folios daraus bedienen. */
    while ((folio = readahead_folio(ractl)) != NULL) {
        u64 frag = folio->index >> (sbi->fragsize_exp - PAGE_SHIFT);
        struct sfs_frag_buf *pb = sfs_get_fragment(inode, frag);
        if (IS_ERR(pb)) {
            /* readahead ist best-effort: Folio einfach nicht uptodate lassen;
               ein späteres read_folio meldet den Fehler synchron. */
            folio_unlock(folio);   /* readahead_folio() liefert gelockte Folios,
                                      die Referenz hält der Caller */
            continue;
        }
        size_t off = (folio->index << PAGE_SHIFT) & (sbi->frag_bytes - 1);
        size_t avail = off < pb->plain_len ? min_t(size_t, pb->plain_len - off,
                                                   folio_size(folio)) : 0;
        if (avail) memcpy_to_folio(folio, 0, pb->plain + off, avail);
        if (avail < folio_size(folio))
            folio_zero_range(folio, avail, folio_size(folio) - avail);
        folio_mark_uptodate(folio);
        folio_unlock(folio);
        sfs_put_fragment(pb);
    }
}
```

`readahead_folio()` entnimmt das nächste Folio und gibt es gelockt zurück; wir müssen es
selbst entsperren (im Gegensatz zu `read_folio`, wo der Fehlerfall genauso läuft). Der
Ein-Eintrag-Fragment-Cache macht die 32 aufeinanderfolgenden Folios desselben Fragments
zu 1 Entschlüsselung. Später optimierbar auf squashfs-Niveau (mehrere Cache-Slots,
`readahead_expand`).

### 3.5 Fragment lesen (Ciphertext von Platte)

```c
/* liest ct_len Bytes ab Container-Byteoffset off (4-KiB-aligned Startblock) */
int sfs_read_ciphertext(struct super_block *sb, u64 start_block, u32 ct_len, u8 *dst)
{
    u32 done = 0;
    while (done < ct_len) {
        struct buffer_head *bh = sb_bread(sb, start_block + (done >> 12));
        if (!bh)
            return -EIO;
        u32 n = min_t(u32, ct_len - done, sb->s_blocksize);
        memcpy(dst + done, bh->b_data, n);
        brelse(bh);
        done += n;
    }
    return 0;
}
```

Puffer: `kmalloc(frag_bytes + 16, GFP_NOFS)`. **Nicht kvmalloc**, solange
`sg_init_one` verwendet wird — vmalloc-Speicher ist physisch nicht zusammenhängend und
für `sg_init_one`/`sg_set_buf` illegal. 132 KiB kmalloc (order-6) kann unter
Speicherdruck scheitern; robustere Variante ohne Kopie: Scatterlist direkt über die
bh-Seiten (`sg_set_page(sg, bh->b_page, len, bh_offset(bh))`) — §5.4.

---

## 4. readdir: dir_emit-Muster

v6.12: nur noch `.iterate_shared` (include/linux/fs.h:2072); `.iterate` wurde in 6.5
entfernt. `iterate_shared` läuft unter geteiltem `i_rwsem` — bei uns (ro) irrelevant,
aber der Handler muss reentrant bzgl. paralleler readdir auf demselben Verzeichnis sein
(keine Mutation von Inode-Zustand ohne Lock).

```c
static int sfs_readdir(struct file *file, struct dir_context *ctx)
{
    struct inode *dir = file_inode(file);

    /* Positionen 0,1 = "." und ".." — Helfer erledigt Emission + ctx->pos:
       v6.12 include/linux/fs.h:3675 dir_emit_dots */
    if (!dir_emit_dots(file, ctx))
        return 0;

    /* ctx->pos ist ein 64-bit-Cookie, das WIR definieren. Anforderungen:
       - stabil über getdents-Aufrufe hinweg (Userspace kann mit telldir/seekdir
         zurückspringen)
       - monoton innerhalb eines Durchlaufs
       Empfehlung: ctx->pos = 2 + Index des Eintrags in der (deterministisch
       sortierten) entschlüsselten Verzeichnisliste. */
    struct sfs_dir_snapshot *snap = sfs_dir_load(dir);   /* Records lesen+entschlüsseln,
                                                            deterministisch geordnet */
    if (IS_ERR(snap))
        return PTR_ERR(snap);

    for (u64 i = ctx->pos - 2; i < snap->count; i++) {
        const struct sfs_dirent *de = &snap->ents[i];
        /* dir_emit: v6.12 include/linux/fs.h:3659–3664
           Rückgabe false = Userspace-Puffer voll → Abbruch OHNE Fehler,
           ctx->pos NICHT weiterschalten (Eintrag wird nächstes Mal wiederholt). */
        if (!dir_emit(ctx, de->name, de->name_len,
                      uuid_to_ino(de->uuid),           /* wie in §2.1 sfs_inode_set */
                      de->dtype))                      /* DT_REG/DT_DIR/DT_LNK/… */
            break;
        ctx->pos++;
    }
    sfs_dir_put(snap);
    return 0;
}

static const struct file_operations sfs_dir_ops = {
    .llseek         = generic_file_llseek,
    .read           = generic_read_dir,     /* read(2) auf Verzeichnis → -EISDIR */
    .iterate_shared = sfs_readdir,
};
```

`dtype`-Abbildung aus `mode`: `fs_umode_to_dtype(mode)` (include/linux/fs_types.h) —
liefert DT_REG/DT_DIR/DT_LNK/DT_UNKNOWN korrekt.

**Fehlerfälle:** I/O-/Integritätsfehler beim Laden der Records → negativer Rückgabewert
(-EIO). `dir_emit == false` ist KEIN Fehler (Puffer voll), Rückgabe 0.

---

## 5. Kernel-Crypto-API (synchron)

Alle drei Allokatoren sind **EXPORT_SYMBOL_GPL** (v6.12 crypto/aead.c:203,
crypto/skcipher.c:838 und :862 [sync-Variante], crypto/shash.c:246) ⇒ §7.

Benötigte Kconfig-Abhängigkeiten (auf Debian-Standardkernel alle =y/m):
`CRYPTO_AES`, `CRYPTO_GCM`, `CRYPTO_XTS`, `CRYPTO_HMAC`, `CRYPTO_SHA256`.
Zur Laufzeit prüfen: `crypto_alloc_*` liefert `ERR_PTR(-ENOENT)`, wenn der Algorithmus
fehlt → als Mount-Fehler -ENOENT/-EINVAL mit klarer Meldung durchreichen.

### 5.1 Allokation (einmal pro Mount, in sfs_crypto_init)

```c
struct sfs_crypto {
    struct crypto_aead          *gcm;      /* "gcm(aes)"  */
    struct crypto_sync_skcipher *xts;      /* "xts(aes)"  */
    struct crypto_shash         *hmac;     /* "hmac(sha256)" für HKDF */
    struct mutex                 gcm_lock; /* setkey+decrypt sind pro tfm nicht
                                              nebenläufig sicher, wenn der Key
                                              pro Fragment wechselt (§5.2) */
    struct mutex                 xts_lock;
    u8                           master_key[32];  /* Caller-Key aus Keyring */
};

int sfs_crypto_init(struct sfs_sb_info *sbi, struct sfs_mount_opts *opts)
{
    struct sfs_crypto *c = &sbi->crypto;

    /* type=0, mask=CRYPTO_ALG_ASYNC ⇒ nur synchrone Implementierungen
       (ASYNC-Bit muss 0 sein). Kein Callback/Completion nötig. */
    c->gcm = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(c->gcm)) return PTR_ERR(c->gcm);
    if (crypto_aead_setauthsize(c->gcm, 16)) goto fail;   /* sfs-Tag = 16 Byte,
        crates/sfs-core/src/crypto/aead.rs:40 */

    c->xts = crypto_alloc_sync_skcipher("xts(aes)", 0, 0); /* immer sync */
    if (IS_ERR(c->xts)) goto fail;

    c->hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);    /* shash = immer sync */
    if (IS_ERR(c->hmac)) goto fail;

    mutex_init(&c->gcm_lock);
    mutex_init(&c->xts_lock);
    /* master_key aus dem Kernel-Keyring holen (opts->key_id):
       key = lookup_user_key(opts->key_id, …) / request_key(); 32 Byte kopieren,
       memzero_explicit auf Zwischenpuffer. Fehler → -ENOKEY. */
    return 0;
fail:
    sfs_crypto_destroy(sbi);
    return -ENOENT;
}
```

Hinweis Nebenläufigkeit: sfs leitet **pro Fragment einen eigenen GCM-Key** ab
(§5.3) ⇒ vor jedem Decrypt `setkey`. `setkey` verändert den tfm-Zustand global ⇒
`gcm_lock` um setkey+decrypt. Das serialisiert die Entschlüsselung pro Mount — für v1
akzeptabel; Skalierungsoption: Pool von N tfms oder `crypto_clone_aead` pro CPU.
(XTS: der 64-Byte-Key ist ctx-unabhängig, `crates/sfs-core/src/crypto/xts.rs:87–93` —
einmal `setkey` beim Mount, danach lock-frei nutzbar, nur der Tweak wechselt.)

### 5.2 GCM-Decrypt-Sequenz (Fragment)

sfs-Fragment-Format: `ciphertext || tag(16)`, **kein** gespeicherter Nonce, **kein AAD**
(Nonce+Key deterministisch abgeleitet; `crates/sfs-core/src/crypto/aead.rs:22–25,
186–197`). Metadaten-Blöcke nutzen dagegen gespeicherten Nonce + AAD + **rohen** Key
(`aead.rs:97–160`) — beide Sequenzen unten.

```c
/* Fragment: plaintext_len = ct_len - 16 */
int sfs_gcm_decrypt(struct sfs_crypto *c,
                    const u8 key[32], const u8 nonce[12],
                    const u8 *aad, unsigned int aad_len,
                    u8 *ct_and_tag, unsigned int ct_len,   /* inkl. 16-Byte-Tag */
                    u8 *plain_out)
{
    struct aead_request *req;
    struct scatterlist sg_src[2], sg_dst[2];
    u8 iv[12];
    int err;

    memcpy(iv, nonce, 12);

    mutex_lock(&c->gcm_lock);
    err = crypto_aead_setkey(c->gcm, key, 32);
    if (err) goto out;

    req = aead_request_alloc(c->gcm, GFP_NOFS);
    if (!req) { err = -ENOMEM; goto out; }

    /* AEAD-SG-Konvention: src = AAD || ciphertext||tag; dst = AAD || plaintext.
       cryptlen = ct_len (Ciphertext INKLUSIVE Tag beim Decrypt). */
    sg_init_table(sg_src, 2);
    sg_init_table(sg_dst, 2);
    if (aad_len) {
        sg_set_buf(&sg_src[0], aad, aad_len);
        sg_set_buf(&sg_dst[0], (void *)aad, aad_len);   /* dst-AAD wird nicht beschrieben,
                                                           muss aber im Layout stehen */
        sg_set_buf(&sg_src[1], ct_and_tag, ct_len);
        sg_set_buf(&sg_dst[1], plain_out, ct_len - 16);
    } else {
        sg_init_one(&sg_src[0], ct_and_tag, ct_len);
        sg_init_one(&sg_dst[0], plain_out, ct_len - 16);
    }

    aead_request_set_callback(req, 0, NULL, NULL);   /* sync: kein Callback */
    aead_request_set_ad(req, aad_len);
    aead_request_set_crypt(req, sg_src, sg_dst, ct_len, iv);

    err = crypto_aead_decrypt(req);   /* 0 = ok; -EBADMSG = Tag-Verifikation
                                         fehlgeschlagen (→ auf -EIO mappen, §3.3) */
    aead_request_free(req);
out:
    mutex_unlock(&c->gcm_lock);
    return err;
}
```

Randbedingungen:
- `sg_init_one`/`sg_set_buf` NUR mit kmalloc-/Slab-/Page-Speicher, nie vmalloc/Stack.
- Puffer für `iv` darf auf dem Stack liegen (wird von sync-Implementierungen kopiert
  bzw. direkt gelesen); `ct`/`plain` nicht.
- In-place ist erlaubt (src==dst-Puffer), spart den zweiten 128-KiB-Puffer:
  `sg_init_one(&sg_dst[0], ct_and_tag, ct_len - 16)` — Plaintext überschreibt den
  Ciphertext-Anfang. Empfohlen.

### 5.3 Schlüssel-/Nonce-Ableitung: HKDF-SHA256 von Hand

**KRITISCH:** `include/crypto/hkdf.h` (`crypto_hkdf_extract`/`crypto_hkdf_expand`)
existiert **erst ab v6.15** (verifiziert: 404 in v6.12/v6.13/v6.14, vorhanden in v6.15).
Auf 6.12 ⇒ HKDF (RFC 5869) selbst über `hmac(sha256)` implementieren:

```c
/* HMAC-SHA256 one-shot */
static int sfs_hmac_sha256(struct crypto_shash *tfm,
                           const u8 *key, unsigned int keylen,
                           const u8 *data, unsigned int len, u8 out[32])
{
    int err = crypto_shash_setkey(tfm, key, keylen);
    if (err) return err;
    SHASH_DESC_ON_STACK(desc, tfm);
    desc->tfm = tfm;
    return crypto_shash_digest(desc, data, len, out);
}

/* RFC 5869: PRK = HMAC(salt, ikm); OKM = T(1)||T(2)||…,
   T(i) = HMAC(PRK, T(i-1) || info || i)  — i ist EIN Byte, beginnend bei 0x01 */
static int sfs_hkdf_sha256(struct crypto_shash *tfm,
                           const u8 *salt, unsigned int salt_len,
                           const u8 *ikm, unsigned int ikm_len,
                           const u8 *info, unsigned int info_len,
                           u8 *okm, unsigned int okm_len)
{
    u8 prk[32], t[32];
    unsigned int tlen = 0, done = 0;
    u8 ctr = 1;
    u8 buf[32 + 64 + 1];   /* T(i-1) || info(<=64) || ctr — info bei sfs max 44 Byte */
    int err;

    if (info_len > 64 || okm_len > 255 * 32)
        return -EINVAL;

    err = sfs_hmac_sha256(tfm, salt, salt_len, ikm, ikm_len, prk);  /* Extract */
    if (err) return err;

    while (done < okm_len) {                                        /* Expand */
        unsigned int p = 0;
        memcpy(buf, t, tlen);              p += tlen;
        memcpy(buf + p, info, info_len);   p += info_len;
        buf[p++] = ctr++;
        err = sfs_hmac_sha256(tfm, prk, 32, buf, p, t);
        if (err) goto out;
        tlen = 32;
        unsigned int n = min(32u, okm_len - done);
        memcpy(okm + done, t, n);
        done += n;
    }
out:
    memzero_explicit(prk, sizeof(prk));
    memzero_explicit(t, sizeof(t));
    memzero_explicit(buf, sizeof(buf));
    return err;
}
```

**Byte-exakte sfs-Ableitungen** (Rust-Referenz; die RustCrypto-`Hkdf::new(Some(salt), ikm)`
entspricht exakt RFC-5869-Extract mit diesem salt):

| Zweck | salt | info | Output | Quelle |
|---|---|---|---|---|
| GCM-Subkey pro Block | `"sfs-gcm-key-salt-v1"` | `"sfs-gcm-key-v1"` ‖ ctx(36) | 32 B | aead.rs:84–94 |
| GCM-Nonce pro Block | `"sfs-gcm-nonce-salt-v1"` | `"sfs-gcm-nonce-v1"` ‖ ctx(36) | 12 B | aead.rs:66–76 |
| XTS-Key (ctx-frei) | `"sfs-xts-key-salt-v1"` | `"sfs-xts-key-v1"` | 64 B | xts.rs:87–93 |
| XTS-Tweak pro Block | `"sfs-xts-tweak-salt-v1"` | `"sfs-xts-tweak-v1"` ‖ ctx(36) | 16 B | xts.rs:99–109 |

IKM ist in allen vier Fällen der 32-Byte-Caller-Key (Master-/Objekt-Key laut Key-Hierarchie,
Auftrag 3). Alle Labels OHNE Nul-Terminator (Rust-`b"…"`-Literale).
**Achtung Doku-Drift:** Der Modul-Doc-Kommentar in aead.rs:1–14 nennt
`salt=b"sfs-gcm-nonce-v1"` — das ist FALSCH/veraltet; maßgeblich ist der Code
(aead.rs:66–76 nutzt `SALT_NONCE="sfs-gcm-nonce-salt-v1"`, info-Präfix `NONCE_INFO`).

`ctx(36)` = `BlockCtx::to_bytes()` (`crates/sfs-core/src/crypto/mod.rs:186–198`):

```
Offset  Größe  Feld       Encoding
0       16     uuid       roh (Objekt-UUID)
16      4      frag       u32 little-endian (Fragmentindex, 0-basiert)
20      8      version    u64 little-endian
```

Decrypt-Pipeline pro Fragment (GCM-Suite, `aead.rs:186–197`):

```
subkey = HKDF(salt_key,   ikm=caller_key, info="sfs-gcm-key-v1"||ctx)[0..32]
nonce  = HKDF(salt_nonce, ikm=caller_key, info="sfs-gcm-nonce-v1"||ctx)[0..12]
                          ^^^^ Nonce aus dem CALLER-Key, NICHT aus dem Subkey!
plain  = GCM-Decrypt(key=subkey, iv=nonce, aad=∅, ct||tag)
```

Metadaten-Pfad (`open_with_nonce`, aead.rs:142–160): Key = Caller-Key **direkt** (keine
Ableitung), Nonce = gespeichert (12 B neben dem Ciphertext), AAD = formatdefiniert
(Auftrag 2/3), Fehler bei Tag-Mismatch.

### 5.4 XTS-Decrypt-Sequenz

```c
int sfs_xts_decrypt(struct sfs_crypto *c, const u8 tweak[16],
                    u8 *buf, unsigned int len)   /* in-place; len >= 16 */
{
    struct scatterlist sg;
    u8 iv[16];
    int err;

    if (len < 16) return -EINVAL;   /* Spiegel der Rust-Garantie xts.rs:41–44 */
    memcpy(iv, tweak, 16);

    SYNC_SKCIPHER_REQUEST_ON_STACK(req, c->xts);
    sg_init_one(&sg, buf, len);
    skcipher_request_set_sync_tfm(req, c->xts);
    skcipher_request_set_callback(req, 0, NULL, NULL);
    skcipher_request_set_crypt(req, &sg, &sg, len, iv);
    err = crypto_skcipher_decrypt(req);
    skcipher_request_zero(req);
    return err;
}
```

Der 64-Byte-XTS-Key wird einmal beim Mount gesetzt:
`crypto_sync_skcipher_setkey(c->xts, xts_key64, 64)` — Kernel-XTS erwartet
data_key(32)‖tweak_key(32), identisch zur Rust-Aufteilung (xts.rs:84–86).
Kernel-`xts(aes)` verarbeitet die GESAMTE Request-Länge als eine XTS-Einheit:
IV = Initial-Tweak, GF(2^128)-Multiplikation pro 16-Byte-Block, Ciphertext-Stealing
für len % 16 != 0 (len ≥ 16). **Byte-Kompatibilität mit der Rust-Seite bei
len % 16 != 0 und bei Fragmenten > 16 Byte muss per Testvektor bewiesen werden**
(Risiko R3 unten) — sfs padded laut xts.rs:38–50 auf ≥16, aber das Verhalten für
„ein Fragment = eine Tweak-Einheit vs. sektorweise Re-Tweaks" ist formatdefinierend
(Auftrag 3 muss die Referenz-Testvektoren liefern).

Zero-Copy-Variante (statt kmalloc+memcpy in §3.5): sg-Tabelle über die bh-Seiten —

```c
struct sg_table sgt;
sg_alloc_table(&sgt, nr_blocks, GFP_NOFS);
struct scatterlist *sg = sgt.sgl;
for (i = 0; i < nr_blocks; i++, sg = sg_next(sg))
    sg_set_page(sg, bh[i]->b_page, min(remaining, 4096u), bh_offset(bh[i]));
```

Nur für `src` verwenden (bdev-Pagecache nicht in-place überschreiben!); dst bleibt ein
eigener Plaintext-Puffer. Für v1: Kopiervariante, Zero-Copy als Perf-Folgeaufgabe.

### 5.5 Fehler-Mapping Crypto → VFS

| Crypto-Fehler | Bedeutung | An VFS |
|---|---|---|
| `crypto_alloc_*` = -ENOENT | Algorithmus fehlt im Kernel | Mount-Fehler -ENOENT + errorf |
| `setkey` = -EINVAL | falsche Keylänge (Bug) | -EIO + WARN_ON_ONCE |
| `crypto_aead_decrypt` = -EBADMSG | Tag-Mismatch = Korruption/Manipulation | -EIO + ratelimited pr_err |
| `crypto_aead_decrypt` = -EINVAL | cryptlen < Tag o. ä. (Bug/Korruptes Längenfeld) | -EUCLEAN oder -EIO |

---

## 6. DKMS + Out-of-tree-Build

### 6.1 Quellbaum

```
sfs-driver/
├── dkms.conf
├── Makefile          (Komfort-Wrapper für manuelle Builds)
├── Kbuild            (die eigentliche Kernel-Build-Beschreibung)
└── *.c, *.h
```

### 6.2 Kbuild

```make
obj-m := sfs.o
sfs-y := super.o inode.o dir.o data.o symlink.o crypto.o
ccflags-y := -Werror=implicit-function-declaration
```

### 6.3 Makefile (Wrapper)

```make
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
```

### 6.4 dkms.conf

```sh
PACKAGE_NAME="sfs"
PACKAGE_VERSION="0.1.0"
BUILT_MODULE_NAME[0]="sfs"
DEST_MODULE_LOCATION[0]="/updates/dkms"
MAKE[0]="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build modules"
CLEAN="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build clean"
AUTOINSTALL="yes"
```

(`MAKE[0]`/`CLEAN` sind bei diesem Standard-Layout optional — DKMS' Default-make
funktioniert, sobald Kbuild/Makefile wie oben existieren; explizit angegeben für
Reproduzierbarkeit.)

Installation auf Debian 13:

```
apt install dkms linux-headers-amd64
cp -r sfs-driver /usr/src/sfs-0.1.0
dkms add     sfs/0.1.0
dkms build   sfs/0.1.0
dkms install sfs/0.1.0        # → /lib/modules/$(uname -r)/updates/dkms/sfs.ko
modprobe sfs
```

**Secure Boot (Debian-Default auf vielen Systemen):** unsignierte Module werden
abgelehnt (`Key was rejected by service`). DKMS ≥ 3.0 signiert automatisch mit dem
MOK-Key, wenn `/var/lib/dkms/mok.key`/`mok.pub` existieren; einmalig
`mokutil --import /var/lib/dkms/mok.pub` + Reboot-Enrollment. In der
Betriebsdokumentation vermerken.

**modules.dep/alias:** `MODULE_ALIAS_FS("sfs")` (§1.1) sorgt dafür, dass
`mount -t sfs` das Modul via `request_module("fs-sfs")` automatisch lädt.

---

## 7. Lizenz-Zwang: MODULE_LICENSE

```c
MODULE_LICENSE("GPL");          /* bedeutet "GPL v2 or later"; "GPL v2" ginge auch */
MODULE_DESCRIPTION("sfs read-only encrypted filesystem");
MODULE_AUTHOR("...");
```

**Zwingend GPL-kompatibel**, weil der Treiber `EXPORT_SYMBOL_GPL`-Symbole nutzt —
verifiziert in v6.12:

| Symbol | Export | Quelle |
|---|---|---|
| `crypto_alloc_aead` | **GPL** | crypto/aead.c:203 |
| `crypto_alloc_skcipher` / `crypto_alloc_sync_skcipher` | **GPL** | crypto/skcipher.c:838, :862 |
| `crypto_alloc_shash` | **GPL** | crypto/shash.c:246 |
| `get_tree_bdev` | non-GPL | fs/super.c:1661 |
| `kill_block_super` | non-GPL | fs/super.c:1717 |
| `sb_set_blocksize` / `sb_min_blocksize` / `set_blocksize` | non-GPL | block/bdev.c:178,191,201 |
| `iget5_locked`, `generic_ro_fops`, `simple_get_link`, `d_splice_alias`, `dir_emit`-Familie (inline) | non-GPL / inline | fs/inode.c:1328 ff., fs/read_write.c:35, fs/libfs.c:1699 |

Ohne `MODULE_LICENSE("GPL")` schlägt bereits das Laden mit
„Unknown symbol crypto_alloc_aead" fehl (GPL-only-Symbole werden proprietären Modulen
nicht aufgelöst) und der Kernel wird als tainted markiert. Da die Crypto-API der Kern
des Treibers ist, gibt es keinen Nicht-GPL-Pfad. Konsequenz fürs Projekt: Der
C-Treiber-Quellcode muss unter GPLv2(+) veröffentlichbar sein — unabhängig von der
Lizenz des Rust-Userspace-Codes.

---

## 8. Zusammenfassende Checkliste der 6.12-spezifischen Punkte

1. `fill_super`-Signatur ist die fs_context-Variante: `(struct super_block *, struct fs_context *)` (fs/super.c:1604–1606).
2. `sb->s_bdev_file` existiert und wird von `setup_bdev_super` gesetzt; `set_blocksize` nimmt seit 6.11 `struct file *` — nur via `sb_min_blocksize`/`sb_set_blocksize` gehen, nie direkt (block/bdev.c:153–201).
3. `read_folio`/`readahead` statt `readpage`/`readpages` (fs.h:399,407); Folios, `folio_mark_uptodate`, `folio_unlock`.
4. Nur `.iterate_shared`, kein `.iterate` mehr (fs.h:2072).
5. Zeitfelder nur über `inode_set_*time*`-Accessoren.
6. `alloc_inode_sb()` statt rohem `kmem_cache_alloc` in `alloc_inode`.
7. `crypto/hkdf.h` gibt es NICHT (erst v6.15) → eigene HKDF-Implementierung (§5.3).
8. `crypto_alloc_*` sind GPL-only → `MODULE_LICENSE("GPL")` (§7).
9. `sg_init_one` niemals mit vmalloc-Speicher; 128-KiB-Ciphertext via kmalloc (v1) oder Page-sg über buffer_heads (v2).
10. GCM-Fragment: Subkey UND Nonce via HKDF aus (Caller-Key, uuid‖frag_le32‖version_le64); Nonce aus dem Caller-Key, nicht dem Subkey; kein AAD; Tag 16 B angehängt; kein Nonce auf Platte.
