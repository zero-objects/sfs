#!/usr/bin/env bash
# DKMS POST_BUILD hook — MOK-sign sfs.ko for Secure Boot hosts (WS12 12.5).
#
# DKMS runs this from the build directory right after `make`, so ./sfs.ko is
# present.  Signing is OPT-IN and best-effort: if no MOK key is configured the
# hook is a no-op (correct on non-Secure-Boot hosts where unsigned modules load
# fine).  Configure the key in /etc/sfs/mok.conf (installed by packaging):
#
#   SFS_MOK_KEY=/var/lib/shim-signed/mok/sfs_mok.key   # or /root/mok/sfs_mok.key
#   SFS_MOK_CRT=/var/lib/shim-signed/mok/sfs_mok.crt
#
# Enroll the certificate ONCE with:  mokutil --import "$SFS_MOK_CRT"  (+ reboot).
# This mirrors the VM's established MOK flow (key at /root/mok/sfs_mok.{key,crt}).
set -euo pipefail

MODULE="./sfs.ko"
[ -f "$MODULE" ] || MODULE="$(find . -name sfs.ko -print -quit 2>/dev/null || true)"
[ -n "${MODULE:-}" ] && [ -f "$MODULE" ] || { echo "sfs sign-hook: no sfs.ko found, skipping"; exit 0; }

# Load config.
SFS_MOK_KEY="${SFS_MOK_KEY:-}"
SFS_MOK_CRT="${SFS_MOK_CRT:-}"
[ -r /etc/sfs/mok.conf ] && . /etc/sfs/mok.conf

if [ -z "$SFS_MOK_KEY" ] || [ -z "$SFS_MOK_CRT" ]; then
    echo "sfs sign-hook: no MOK key configured (/etc/sfs/mok.conf) — leaving module unsigned"
    exit 0
fi
if [ ! -r "$SFS_MOK_KEY" ] || [ ! -r "$SFS_MOK_CRT" ]; then
    echo "sfs sign-hook: MOK key/cert not readable — leaving module unsigned" >&2
    exit 0
fi

# Locate sign-file for the kernel we are building against.
KVER="${kernelver:-$(uname -r)}"
SIGN_FILE=""
for c in \
    "/usr/src/linux-headers-$KVER/scripts/sign-file" \
    "/lib/modules/$KVER/build/scripts/sign-file" \
    "$(command -v kmodsign 2>/dev/null || true)"; do
    [ -n "$c" ] && [ -x "$c" ] && { SIGN_FILE="$c"; break; }
done
[ -n "$SIGN_FILE" ] || { echo "sfs sign-hook: sign-file not found for $KVER — skipping" >&2; exit 0; }

echo "sfs sign-hook: signing $MODULE with $SFS_MOK_KEY ($KVER)"
"$SIGN_FILE" sha256 "$SFS_MOK_KEY" "$SFS_MOK_CRT" "$MODULE"
echo "sfs sign-hook: signed."
