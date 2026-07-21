#!/usr/bin/env bash
# install.sh — install the sfs OS-integration layer (WS12 12.5).
#
# Places the userspace binaries, udev rule and systemd units, and (optionally)
# registers the kernel module with DKMS.  Idempotent; re-runnable.
#
#   ./packaging/install.sh [--dkms] [--no-build] [--prefix /usr/local]
#
#   --dkms      Also `dkms add/build/install` the kernel module from kernel/.
#   --no-build  Skip `cargo build --release` (use existing target/release bins).
#   --prefix P  Where non-mount helpers go (default /usr/local).  mkfs/fsck/
#               mount.sfs ALWAYS go to /sbin (util-linux only searches there).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="/usr/local"
DO_DKMS=0
DO_BUILD=1
while [ $# -gt 0 ]; do
    case "$1" in
        --dkms) DO_DKMS=1 ;;
        --no-build) DO_BUILD=0 ;;
        --prefix) PREFIX="$2"; shift ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "install.sh: unknown arg $1" >&2; exit 1 ;;
    esac
    shift
done

[ "$(id -u)" = 0 ] || { echo "install.sh: must run as root" >&2; exit 1; }

SBIN="$PREFIX/sbin"
REL="$REPO/target/release"
install -d "$SBIN" /sbin /etc/sfs /lib/udev/rules.d /etc/systemd/system

if [ "$DO_BUILD" = 1 ]; then
    echo "== building release binaries =="
    ( cd "$REPO" && cargo build --release -p zero-sfs-cli -p zero-sfs-tools )
    ( cd "$REPO" && cargo build --release -p zero-sfs-mount --features fuse ) || \
        echo "install.sh: sfs-mount (FUSE) build skipped/failed — FUSE fallback unavailable"
fi

echo "== installing binaries =="
# util-linux helpers MUST live in /sbin with the dotted names.
install -m 0755 "$REL/mkfs-sfs"  /sbin/mkfs.sfs
install -m 0755 "$REL/fsck-sfs"  /sbin/fsck.sfs
install -m 0755 "$REL/mount-sfs" /sbin/mount.sfs
# Daemon, prober, maintenance wrapper, WS11 ioctl CLI, FUSE binary.
install -m 0755 "$REL/sfsd"            "$SBIN/sfsd"
install -m 0755 "$REL/sfs-blkid-probe" "$SBIN/sfs-blkid-probe"
install -m 0755 "$REPO/packaging/sbin/sfs-maintain" "$SBIN/sfs-maintain"
[ -f "$REL/sfs-mount" ] && install -m 0755 "$REL/sfs-mount" "$SBIN/sfs-mount"
# sfsctl is a C tool built under kernel/tools.
if [ -x "$REPO/kernel/tools/sfsctl" ]; then
    install -m 0755 "$REPO/kernel/tools/sfsctl" "$SBIN/sfsctl"
else
    echo "install.sh: kernel/tools/sfsctl not built — run 'make -C kernel/tools sfsctl' for the maintenance timer"
fi

echo "== installing udev rule =="
install -m 0644 "$REPO/packaging/udev/62-sfs.rules" /lib/udev/rules.d/62-sfs.rules
udevadm control --reload 2>/dev/null || true

echo "== installing systemd units =="
for u in sfsd.socket sfsd.service sfs-maintain@.service sfs-maintain@.timer; do
    install -m 0644 "$REPO/packaging/systemd/$u" /etc/systemd/system/"$u"
done

echo "== installing config defaults =="
[ -f /etc/sfs/maintain.conf ] || install -m 0644 "$REPO/packaging/etc/sfs/maintain.conf" /etc/sfs/maintain.conf
[ -f /etc/sfs/sfsd.conf ]     || install -m 0640 "$REPO/packaging/etc/sfs/sfsd.conf.example" /etc/sfs/sfsd.conf
[ -f /etc/sfs/mok.conf ]      || install -m 0640 "$REPO/packaging/etc/sfs/mok.conf.example" /etc/sfs/mok.conf
systemctl daemon-reload 2>/dev/null || true

if [ "$DO_DKMS" = 1 ]; then
    echo "== registering kernel module with DKMS =="
    SRC=/usr/src/sfs-0.1
    rm -rf "$SRC"; install -d "$SRC"
    cp -a "$REPO/kernel/." "$SRC/"
    chmod +x "$SRC/dkms-sign-hook.sh" 2>/dev/null || true
    dkms add    -m sfs -v 0.1 || true
    dkms build  -m sfs -v 0.1
    dkms install -m sfs -v 0.1 --force
fi

echo "== done =="
echo "Try:  mkfs.sfs --insecure-test-key -L test /dev/loopX"
echo "      mount -t sfs -o insecure-test-key /dev/loopX /mnt/x"
echo "      lsblk -f /dev/loopX     # should show sfs + UUID"
