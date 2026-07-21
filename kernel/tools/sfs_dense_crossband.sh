#!/usr/bin/env bash
# Regression (#64): a DENSE single-writer append that crosses one or more
# derived-fragsize band boundaries (D-2b re-chunk) must commit byte-exact with
# NO truncation.
#
# Root cause it guards: sfs_cow_write cached fragsize_exp in a local across the
# loop, but sfs_cow_get_entry can flush-commit mid-loop on the RAM cap; a flush
# that crosses a fragsize band re-derives si->fragsize_exp, so the following
# fragments were keyed at the STALE exponent. Those mis-indexed w_cow entries
# made the next commit reject the whole batch (-EINVAL) and truncate the file
# to the last good commit — silent data loss at the first band crossing under
# sustained RAM pressure.
#
# Method: freeze the stream at exp=12 with a small head write, then stream the
# rest in ONE dense dd so the writer-driven RAM-cap flush lands mid-write while
# the file grows past 16 MiB / 256 MiB / 512 MiB / … (each a band boundary).
# Verify staged read, remount read, and the Rust reference reader (sfs-cat) all
# equal the source bytes at the exact source size.
#
# Usage: sfs_dense_crossband.sh [cipher] [size_bytes] [rust-bin-dir]
#   cipher     : none|xts|gcm            (default none)
#   size_bytes : total file size         (default 750000000 ≈ 715 MiB, crosses
#                                          bands exp 12→17 — the #64 repro size)
#
# NOTE on multi-GiB sizes: a stream frozen at the floor exponent that appends
# through MANY bands re-chunks at each one, copying the whole stream to history
# every time (transient write amplification ≈3×+ the final size). Sizes in the
# multi-GiB range therefore need a proportionally larger container than the 5×
# budget below — that is a space cost of the re-chunk design, not a #64 relapse
# (an undersized container fails with -EIO/-ENOSPC, distinct from the #64 -22).
set -u

CIPHER="${1:-none}"
SIZE="${2:-750000000}"
here="$(cd "$(dirname "$0")" && pwd)"
BINS="${3:-$here/../../target/release}"
MKFS="$here/sfs_mkfs"
CAT="$BINS/sfs-cat"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sfs-crossband.XXXXXX")"
IMG="$WORK/cb.sfs"
SRC="$WORK/src.bin"
MNT="$WORK/mnt"
mkdir -p "$MNT"
cleanup() {
	umount -l "$MNT" 2>/dev/null
	[ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

# Container must hold the file PLUS the cumulative re-chunk tail history: a
# stream frozen at the floor exponent re-chunks at every band boundary it grows
# past (16/32/64/…MiB), and each re-chunk copies the whole stream to the tail as
# pure history. That sums to ≈2× the final size, so budget 5× + 1 GiB slack.
CAP=$(( SIZE * 5 + 1073741824 ))
"$MKFS" --cipher "$CIPHER" "$IMG" >/dev/null 2>&1 || { echo "FAIL: mkfs"; exit 1; }
truncate -s "$CAP" "$IMG"
head -c "$SIZE" /dev/urandom > "$SRC"
EXP=$(sha256sum < "$SRC" | cut -d' ' -f1)

LOOP=$(losetup -f --show "$IMG") || { echo "FAIL: losetup"; exit 1; }
dmesg -C 2>/dev/null || true
mount -t sfs -o insecure_test_key "$LOOP" "$MNT" || { echo "FAIL: mount"; exit 1; }

# Freeze exp=12 with a COMMITTED 8 MiB head (fsync ⇒ a real committed record at
# the floor exponent, so the appends below take the committed-CoW path — a
# never-committed sequential file would instead stream at the fixed stream
# exponent and never re-chunk). Then ONE dense dd for the remainder so the
# writer-driven RAM-cap flush-commit fires mid-write across the band boundaries.
dd if="$SRC" of="$MNT/f.bin" bs=1M count=8 conv=notrunc,fsync status=none
dd if="$SRC" of="$MNT/f.bin" bs=1M skip=8 seek=8 conv=notrunc,fsync status=none 2>"$WORK/dderr"
DDRC=$?
sync
GOTSZ=$(stat -c%s "$MNT/f.bin" 2>/dev/null)
STAGED=$(sha256sum < "$MNT/f.bin" | cut -d' ' -f1)
CF=$(dmesg 2>/dev/null | grep -c "commit failed" || true)
umount -l "$MNT"

mount -t sfs -o ro,insecure_test_key "$LOOP" "$MNT" || { echo "FAIL: remount"; exit 1; }
REMSZ=$(stat -c%s "$MNT/f.bin" 2>/dev/null)
REMNT=$(sha256sum < "$MNT/f.bin" | cut -d' ' -f1)
umount -l "$MNT"

# Rust reference reader on the raw container image (byte-authority).
RUST=$("$CAT" "$IMG" /f.bin 2>/dev/null | sha256sum | cut -d' ' -f1)

echo "cipher=$CIPHER size=$SIZE ddrc=$DDRC gotsz=$GOTSZ remsz=$REMSZ commitfail=$CF"
echo "  expected=$EXP"
echo "  staged  =$STAGED"
echo "  remount =$REMNT"
echo "  rust    =$RUST"

if [ "$DDRC" = 0 ] && [ "$GOTSZ" = "$SIZE" ] && [ "$REMSZ" = "$SIZE" ] && \
   [ "$STAGED" = "$EXP" ] && [ "$REMNT" = "$EXP" ] && [ "$RUST" = "$EXP" ] && \
   [ "$CF" = 0 ]; then
	echo "PASS dense-crossband $CIPHER"
	exit 0
fi
echo "FAIL dense-crossband $CIPHER (truncation / -EINVAL / sha mismatch)"
exit 1
