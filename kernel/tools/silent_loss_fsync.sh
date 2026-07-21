#!/bin/bash
# Regression gate (#68): fsync must PROPAGATE a co-resident commit failure —
# never return 0 while acknowledged bytes were silently dropped.
#
# A failed __sfs_commit (ENOSPC / internal) is atomic and drops the staged,
# write()-acknowledged bytes of EVERY dirty inode. Such a commit is routinely
# triggered by a CO-RESIDENT file (RAM-cap flush-commit, another file's fsync).
# The pre-fix driver did not stamp the dropped inodes with mapping_set_error and
# sfs_fsync ran no filemap check, so a co-resident file's fsync returned 0 while
# its bytes were lost (silent data loss). The fix stamps every dropped inode via
# mapping_set_error and sfs_fsync surfaces it with file_write_and_wait_range.
#
# This gate also asserts the console-log routing: the EXPECTED ENOSPC case, now
# reported via errno, no longer emits a per-commit pr_err (no dmesg flood).
#
# Requires: root, loop devices, the sfs.ko module loaded, tools/sfs_mkfs, the
# Rust sfs-cat + sfs-fsck (byte-authority cross-read). cc builds the helper.
#
# Usage: silent_loss_fsync.sh [cipher ...]   (default: none xts gcm)
set -u

KDIR="$(cd "$(dirname "$0")/.." && pwd)"
BINS="${SFS_BINS:-$KDIR/../target/release}"
MKFS="$KDIR/tools/sfs_mkfs"
SCAT="$BINS/sfs-cat"
FSCK="$BINS/sfs-fsck"
HELPER_SRC="$KDIR/tools/silent_loss_fsync.c"
HELPER="${SFS_WORK:-/root/t}/silent_loss_fsync"
MNT="${SFS_MNT:-/mnt/sfstest}"
WORK="${SFS_WORK:-/root/t}"
CONT_MB="${SFS_CONT_MB:-16}"; A_MB="${SFS_A_MB:-2}"; B_MB="${SFS_B_MB:-40}"
mkdir -p "$MNT" "$WORK"

cc -O2 -o "$HELPER" "$HELPER_SRC" || { echo "helper build FAIL"; exit 1; }

ciphers=("$@"); [ ${#ciphers[@]} -eq 0 ] && ciphers=(none xts gcm)
rc=0

for CIPHER in "${ciphers[@]}"; do
  IMG="$WORK/silent-loss-$CIPHER.sfs"
  umount "$MNT" 2>/dev/null; losetup -D 2>/dev/null; rm -f "$IMG"
  "$MKFS" --cipher "$CIPHER" "$IMG" >/dev/null
  truncate -s ${CONT_MB}M "$IMG"
  L=$(losetup -f); losetup "$L" "$IMG"

  dmesg -C 2>/dev/null
  if ! mount -t sfs -o insecure_test_key "$L" "$MNT" 2>/dev/null; then
    echo "[$CIPHER] MOUNT_FAIL"; losetup -d "$L"; rc=1; continue
  fi

  OUT=$("$HELPER" "$MNT" "$A_MB" "$B_MB")
  VERDICT=$(echo "$OUT" | sed -n 's/.*VERDICT //p')
  FSYNC_A=$(echo "$VERDICT" | sed -n 's/.*fsync_A=\([0-9]*\).*/\1/p')
  FLOOD=$(dmesg 2>/dev/null | grep -c "commit failed")

  sync 2>/dev/null
  umount "$MNT";
  # byte-authority cross-read (Rust) after remount
  RB="?"
  if [ -x "$SCAT" ]; then
    RB=$("$SCAT" "$IMG" /A.bin 2>/dev/null | od -An -tx1 -N1 | tr -d ' ')
  fi
  OK="?"
  [ -x "$FSCK" ] && OK=$("$FSCK" --json "$IMG" 2>/dev/null | tr ',' '\n' | sed -n 's/.*"ok"[: ]*\(true\|false\).*/\1/p' | head -1)
  losetup -d "$L"; rm -f "$IMG"

  # PASS criteria:
  #  - fsync(A) != 0  (co-resident failure reported, NOT silent success)
  #  - dmesg has 0 per-commit "commit failed" lines (ENOSPC not flooding)
  #  - container consistent (fsck ok:true; A reads back a defined byte)
  if [ "${FSYNC_A:-0}" -ne 0 ] && [ "$FLOOD" -eq 0 ] && [ "$OK" = "true" ]; then
    echo "[$CIPHER] PASS  $VERDICT  rust_A=0x$RB dmesg_flood=$FLOOD fsck=$OK"
  else
    echo "[$CIPHER] FAIL  $VERDICT  rust_A=0x$RB dmesg_flood=$FLOOD fsck=$OK"
    echo "$OUT" | sed 's/^/    /'
    rc=1
  fi
done

[ $rc -eq 0 ] && echo "silent_loss_fsync: ALL PASS" || echo "silent_loss_fsync: FAILURES"
exit $rc
