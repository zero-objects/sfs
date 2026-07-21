# libblkid sfs probe (contrib, WS12 12.4)

`sfs.c` is a drop-in libblkid superblock prober that teaches the **system**
`blkid` / `lsblk -f` / `mount` stack to recognise sfs volumes natively.

## What ships today vs. what needs upstream

| Path | Status |
|------|--------|
| `sfs-blkid-probe` binary + `packaging/udev/62-sfs.rules` | **Ships now.** A udev `IMPORT{program}` rule runs the tiny read-only prober and sets `ID_FS_TYPE=sfs`, `ID_FS_UUID`, `ID_FS_LABEL`, creating `/dev/disk/by-uuid` + `by-label` symlinks. `lsblk -f` and `mount UUID=…`/fstab work. |
| `blkid <dev>` (the CLI, no udev) printing `TYPE="sfs"` | **Needs upstream.** The CLI uses libblkid's built-in probe table, which we cannot patch on an installed system. `sfs.c` is the probe to submit to util-linux. |

The udev rule delivers everything the DoD needs (by-uuid mounting, `lsblk -f`);
the libblkid patch below is the clean long-term home so the raw `blkid` CLI and
any third-party libblkid consumer also identify sfs without the rule.

## Applying to util-linux

1. Copy `sfs.c` to `libblkid/src/superblocks/sfs.c`.
2. Register it in `libblkid/src/superblocks/superblocks.c`:
   - add `extern const struct blkid_idinfo sfs_idinfo;`
   - add `&sfs_idinfo,` to the `idinfos[]` array (near the other filesystems).
3. Add `sfs.c` to `libblkid/src/superblocks/Makemodule.am`.
4. Rebuild util-linux; `blkid <dev>` now prints `TYPE="sfs" UUID="…" LABEL="…"`.

## Signature

- Detection magic: `sfs\0v1\0\0` at byte offset 0 (the container header magic).
- UUID/LABEL: the advisory identity block at offset 512 (see `sfs.c` header
  comment and `crates/sfs-cli/src/identity.rs`).  It is outside the
  authenticated container header and carries no secret — it only names the
  volume; all crypto guarantees stay on the header + per-record AEAD.
