#!/usr/bin/env bash
# WS6 6.2 — end-to-end roundtrip harness.
#
# For each cipher × scenario:
#   1. build a base container (a Rust-written golden of that cipher);
#   2. apply a scripted mutation batch via sfs_mut (the SAME portable core the
#      kernel compiles), emitting a manifest + a cowcheck .expect;
#   3. (i)   sfs_verify --image: manifest diff (size+sha + #type + name-level
#            readdir + #attr) through the kernel object code;
#   4. (ii)  sfs-fsck: the Rust engine's structural check must be green;
#   5. (iii) sfs_cowcheck.sh: Rust sfs-cat SHA of every file + MVCC history
#            (`sfs-cat --version`) + sfs-stat attr + negative lookups;
#   6. (iv)  BOTH DIRECTIONS (write-06): the Rust engine opens the SAME
#            container, writes Y, and the kernel object code re-reads it —
#            sfs-cat(rust) SHA == sfs_verify --cat(kernel) SHA.
#
# The scenarios deliberately batch many namespace + content ops into ONE
# publish (no intermediate publish): sfs_mut asserts, for every publish, that
# the live overlay readdir (trie ∪ ns) already equals the shadow AND that the
# committed trie + content equals the shadow afterwards — the check that makes
# the WS4 ns-smoke "always remount, never test the live overlay" blind spot
# impossible to reintroduce.
#
# Usage: roundtrip.sh [golden-dir] [rust-release-bin-dir]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
GOLDEN="${1:-/tmp/sfs-golden}"
BINS="${2:-$here/../../target/release}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sfs-roundtrip.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

MUT="$here/sfs_mut"
VERIFY="$here/sfs_verify"
COWCHECK="$here/sfs_cowcheck.sh"
fail=0

sha() { "$BINS/sfs-cat" "$1" "$2" | shasum -a 256 | cut -d' ' -f1; }

# ── scenario scripts ─────────────────────────────────────────────────────────
# A "flat" batch (many ops, ONE publish) and a "deep" batch exercising nested
# paths + directory-prefix rename (the deep-readdir path the count-only smoke
# could not see).
scen_flat="$WORK/flat.script"
cat > "$scen_flat" <<'EOF'
create /rt_a 5000 11
create /rt_b 200000 12
mkdir /rt_dir
symlink /rt_link /hello.txt
write /rt_a 100 300 21
write /rt_b 65000 8000 22
chmod /hello.txt 0640
publish
overwrite /rt_a 0 40 31
truncate /rt_b 3000
extend /rt_b 90000
rename /rt_a /rt_a_moved
unlink /rt_dir
publish
defrag
trim
verify
EOF

scen_deep="$WORK/deep.script"
cat > "$scen_deep" <<'EOF'
mkdir /deep
mkdir /deep/x
create /deep/x/f1 4096 41
create /deep/x/f2 100000 42
mkdir /deep/x/y
create /deep/x/y/f3 8192 43
symlink /deep/x/y/l1 /deep/x/f1
publish
write /deep/x/f2 50000 20000 44
truncate /deep/x/f2 12000
rename /deep/x/f1 /deep/x/f1r
unlink /deep/x/y/f3
publish
verify
EOF

run_scenario() { # <cipher-variant> <base-golden> <scenario-file> <sign-seed|"">
	local variant="$1" base="$2" script="$3" seed="$4"
	local tag="$variant-$(basename "$script" .script)"
	local img="$WORK/$tag.sfs" man="$WORK/$tag.manifest" exp="$WORK/$tag.sfs.expect"
	local seedarg=()

	printf '\n=== roundtrip: %s ===\n' "$tag"
	cp "$GOLDEN/golden-$base.sfs" "$img"
	[ -n "$seed" ] && seedarg=(--sign-seed "$seed")

	# (mutate) — sfs_mut runs the live==committed==shadow assertions itself.
	if ! "$MUT" "$img" ${seedarg[@]+"${seedarg[@]}"} --script "$script" \
		--manifest "$man" --expect "$exp"; then
		echo "  FAIL: sfs_mut ($tag)"; fail=1; return
	fi
	# (i) kernel-objectcode manifest diff
	if ! "$VERIFY" --image "$img" "$man" "$tag"; then
		echo "  FAIL: sfs_verify --image ($tag)"; fail=1; return
	fi
	# (ii) Rust structural check
	if ! "$BINS/sfs-fsck" "$img" >/dev/null; then
		echo "  FAIL: sfs-fsck ($tag)"; fail=1; return
	fi
	# (iii) Rust content + history + attr + negatives
	if ! "$COWCHECK" "$img" "$BINS" >/dev/null; then
		echo "  FAIL: sfs_cowcheck ($tag)"; "$COWCHECK" "$img" "$BINS" | tail; fail=1; return
	fi
	# (iv) both directions — Rust writes, kernel object code re-reads.
	if [ -z "$seed" ]; then
		# pick a plain file the scenario left live
		local probe
		probe=$("$BINS/sfs-ls" "$img" | grep -E '^/(hello|len|big|sparse)' | head -1)
		if [ -n "$probe" ]; then
			"$BINS/sfs-write" "$img" write "$probe" 0 64 200
			local rsha csha
			rsha=$(sha "$img" "$probe")
			csha=$("$VERIFY" --cat "$img" "$probe")
			if [ "$rsha" != "$csha" ]; then
				echo "  FAIL: both-directions $probe (rust=$rsha kernel=$csha)"; fail=1; return
			fi
			echo "  ok  both-directions: rust-write($probe) == kernel-read"
		fi
	else
		echo "  (both-directions skipped: signed container — Rust write needs the signing key)"
	fi
	echo "  == roundtrip $tag: PASS =="
}

for cfg in "none none" "xts xts" "gcm gcm"; do
	set -- $cfg
	run_scenario "$1" "$2" "$scen_flat" ""
	run_scenario "$1" "$2" "$scen_deep" ""
done
# Signed container (Fresh-signing through the same core).
run_scenario "signed-gcm" "signed-gcm" "$scen_flat" \
	5151515151515151515151515151515151515151515151515151515151515151

echo
if [ "$fail" = 0 ]; then
	echo "== roundtrip: ALL PASS =="
else
	echo "== roundtrip: FAIL =="
fi
exit "$fail"
