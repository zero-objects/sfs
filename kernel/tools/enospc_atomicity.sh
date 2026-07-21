#!/bin/bash
# Regression gate (#66): create/first-write ENOSPC atomicity.
#
# A `->create` publishes the file NAME in the namespace; the first content
# write is materialised by a LATER commit. If the device runs out of space
# exactly at that boundary, the pre-fix driver left a HEADLESS namespace entry:
# a name in key_root with NO backing head record. `sfs-fsck` reported
# `ok:false` ("no record for path") and a mount showed the file as
# `??????????` with `stat` failing (-ENOENT).
#
# The fix guarantees the D-20 atomic-commit intent: a name is published into
# key_root ONLY together with its head record. At an ENOSPC boundary the file
# is therefore either a valid 0-byte/partial file OR cleanly absent — never
# headless. This reproduces BOTH triggers:
#   1. buffer-all (GCM): the create's failed content commit drains the fresh
#      inode; a later commit must NOT re-publish the orphaned name.
#   2. streaming (NONE/XTS): a write that breaks mid-stream (w_stream_broken)
#      is skipped at commit; its name must NOT be published.
#
# Requires: root, loop devices, the sfs.ko module loaded, and the Rust
# `sfs-fsck` binary. Fills a 1 GiB container with 64 MiB fsync'd files until
# ENOSPC, then asserts `sfs-fsck ok:true`.
#
# Usage: enospc_atomicity.sh [cipher ...]   (default: none xts gcm)
set -u

KDIR="$(cd "$(dirname "$0")/.." && pwd)"
BINS="${SFS_BINS:-$KDIR/../target/release}"
MKFS="$KDIR/tools/sfs_mkfs"
FSCK="$BINS/sfs-fsck"
MNT="${SFS_MNT:-/mnt/enospc-atomicity}"
WORK="${SFS_WORK:-/root/t}"
mkdir -p "$MNT" "$WORK"

ciphers=("$@"); [ ${#ciphers[@]} -eq 0 ] && ciphers=(none xts gcm)
rc=0

for CIPHER in "${ciphers[@]}"; do
  IMG="$WORK/enospc-atomicity-$CIPHER.sfs"
  umount "$MNT" 2>/dev/null
  rm -f "$IMG"
  "$MKFS" --cipher "$CIPHER" "$IMG" >/dev/null
  truncate -s 1G "$IMG"
  L=$(losetup -f); losetup "$L" "$IMG"
  if ! mount -t sfs -o insecure_test_key "$L" "$MNT"; then
    echo "[$CIPHER] MOUNT_FAIL"; losetup -d "$L"; rc=1; continue
  fi
  i=0; last=""; FAILED=""
  while :; do
    i=$((i+1))
    if dd if=/dev/urandom of="$MNT/f_$i.bin" bs=1M count=64 conv=fsync \
         status=none 2>/dev/null; then
      last=$i
    else
      FAILED=$i; break
    fi
    [ $i -gt 40 ] && break
  done
  sync
  umount "$MNT"; losetup -d "$L"

  ok=$("$FSCK" --json "$IMG" 2>/dev/null | tr ',' '\n' | sed -n 's/.*"ok"[: ]*\(true\|false\).*/\1/p' | head -1)
  if [ "$ok" = "true" ]; then
    echo "[$CIPHER] PASS  last_ok=f_$last failed=f_$FAILED  fsck ok:true"
  else
    echo "[$CIPHER] FAIL  last_ok=f_$last failed=f_$FAILED  fsck ok:$ok (HEADLESS ENTRY)"
    "$FSCK" "$IMG" 2>&1 | grep -E "catalog_issues|crc_failures|path /f_" | head -4
    rc=1
  fi
  rm -f "$IMG"
done

[ $rc -eq 0 ] && echo "enospc_atomicity: ALL PASS" || echo "enospc_atomicity: FAILURES"
exit $rc
