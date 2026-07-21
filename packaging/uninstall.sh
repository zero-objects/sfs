#!/usr/bin/env bash
# uninstall.sh — remove the sfs OS-integration layer (WS12 12.5).
set -euo pipefail
PREFIX="${1:-/usr/local}"
SBIN="$PREFIX/sbin"
[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }

rm -f /sbin/mkfs.sfs /sbin/fsck.sfs /sbin/mount.sfs
rm -f "$SBIN/sfsd" "$SBIN/sfs-blkid-probe" "$SBIN/sfs-maintain" "$SBIN/sfs-mount" "$SBIN/sfsctl"
rm -f /lib/udev/rules.d/62-sfs.rules
udevadm control --reload 2>/dev/null || true
for u in sfsd.socket sfsd.service sfs-maintain@.service sfs-maintain@.timer; do
    systemctl disable --now "$u" 2>/dev/null || true
    rm -f /etc/systemd/system/"$u"
done
systemctl daemon-reload 2>/dev/null || true
dkms remove -m sfs -v 0.1 --all 2>/dev/null || true
echo "uninstall.sh: removed binaries, udev rule and units (left /etc/sfs/*.conf in place)."
