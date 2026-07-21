#!/usr/bin/env bash
# WS3/WS5 Rust re-verification of a kernel-mutated container (write-07):
#   1. `sfs-fsck` must pass on the mutated image (exit 0);
#   2. every `cur <path> <size> <sha>` line of <image>.expect must match
#      `sfs-cat <image> <path>` (current head content across the
#      kernel-written CoW records);
#   3. every `ver <path> <dot> <size> <sha>` line must match
#      `sfs-cat --version <dot>` — the MVCC history resolve across the
#      kernel-written parent edge still reconstructs the PRE-mutation bytes;
#   4. every `attr <path> <expected>` line must match sfs-stat's decoded
#      `Attr : <type> mode=<octal> uid=.. gid=.. mtime=<s>.<ns>` output —
#      the RUST side authenticates + decodes the kernel-written meta stream
#      (WS5 5.2);
#   5. every `neg <path>` line must FAIL to resolve (removed/renamed-away
#      keys, WS4).
#
# Usage: sfs_cowcheck.sh <image.sfs> <rust-release-bin-dir>
set -euo pipefail

img=$1
bins=$2
expect="$img.expect"
fail=0

sha_stdin() { shasum -a 256 | cut -d' ' -f1; }

echo "  fsck: $img"
"$bins/sfs-fsck" "$img" >/dev/null || { echo "  FAIL: sfs-fsck"; exit 1; }

while IFS=$'\t' read -r kind a b c d; do
	case "$kind" in
	cur)
		path=$a; size=$b; want=$c
		got=$("$bins/sfs-cat" "$img" "$path" | sha_stdin)
		gsz=$("$bins/sfs-cat" "$img" "$path" | wc -c | tr -d ' ')
		if [ "$got" != "$want" ] || [ "$gsz" != "$size" ]; then
			echo "  FAIL cur $path: sha/size mismatch ($gsz vs $size)"
			fail=1
		else
			echo "  ok  cur $path ($size bytes)"
		fi
		;;
	ver)
		path=$a; dot=$b; size=$c; want=$d
		got=$("$bins/sfs-cat" --version "$dot" "$img" "$path" | sha_stdin)
		gsz=$("$bins/sfs-cat" --version "$dot" "$img" "$path" | wc -c | tr -d ' ')
		if [ "$got" != "$want" ] || [ "$gsz" != "$size" ]; then
			echo "  FAIL ver $path@$dot: sha/size mismatch ($gsz vs $size)"
			fail=1
		else
			echo "  ok  ver $path@$dot ($size bytes, history resolve)"
		fi
		;;
	attr)
		path=$a; want=$b
		got=$("$bins/sfs-stat" "$img" "$path" | sed -n 's/^Attr           : //p')
		if [ "$got" != "$want" ]; then
			echo "  FAIL attr $path: got '$got' want '$want'"
			fail=1
		else
			echo "  ok  attr $path ($want)"
		fi
		;;
	neg)
		path=$a
		if "$bins/sfs-cat" "$img" "$path" >/dev/null 2>&1; then
			echo "  FAIL neg $path: still resolves"
			fail=1
		else
			echo "  ok  neg $path (absent)"
		fi
		;;
	negver)
		# WS11: a version dropped by the retention pass (chain
		# compacted) must NO LONGER resolve via history checkout.
		path=$a; dot=$b
		if "$bins/sfs-cat" --version "$dot" "$img" "$path" >/dev/null 2>&1; then
			echo "  FAIL negver $path@$dot: still resolves"
			fail=1
		else
			echo "  ok  negver $path@$dot (version dropped)"
		fi
		;;
	negls)
		path=$a
		if "$bins/sfs-ls" "$img" 2>/dev/null | grep -qF "$path"; then
			echo "  FAIL negls $path: still listed"
			fail=1
		else
			echo "  ok  negls $path (unlisted)"
		fi
		;;
	esac
done < "$expect"

[ "$fail" = 0 ] && echo "  == cowcheck: PASS ==" || { echo "  == cowcheck: FAIL =="; exit 1; }
