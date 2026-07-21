#!/usr/bin/env bash
# run_e2e.sh — Build and run the sfs C E2E smoke test.
#
# Must be called from the workspace root (e.g. `bash crates/sfs-ffi/tests/run_e2e.sh`).
# Requires: cc (clang or gcc), cargo.
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
LIB_DIR="$WORKSPACE_ROOT/target/release"
HEADER_DIR="$WORKSPACE_ROOT/crates/sfs-ffi/include"
SRC="$WORKSPACE_ROOT/crates/sfs-ffi/tests/e2e_smoke.c"
OUT="/tmp/sfs_e2e_smoke_bin"

echo "=== Building sfs-ffi (release) ==="
cd "$WORKSPACE_ROOT"
cargo build --release -p zero-sfs-ffi

echo ""
echo "=== Compiling C E2E smoke test ==="
OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    # macOS: link against the dylib; set DYLD_LIBRARY_PATH at runtime.
    cc "$SRC" \
       -I "$HEADER_DIR" \
       -L "$LIB_DIR" \
       -lsfs_ffi \
       -o "$OUT"
    echo "Compile OK (macOS dylib)"
    DYLD_LIBRARY_PATH="$LIB_DIR" "$OUT"

elif [ "$OS" = "Linux" ]; then
    # Linux: link statically to avoid LD_LIBRARY_PATH hassle in CI.
    cc "$SRC" \
       -I "$HEADER_DIR" \
       "$LIB_DIR/libsfs_ffi.a" \
       -ldl -lpthread -lm \
       -o "$OUT"
    echo "Compile OK (Linux static)"
    "$OUT"

else
    # Windows (Git Bash / MSYS2): link against the import lib.
    cc "$SRC" \
       -I "$HEADER_DIR" \
       "$LIB_DIR/sfs_ffi.dll.lib" \
       -o "$OUT"
    echo "Compile OK (Windows)"
    "$OUT"
fi

echo ""
echo "E2E smoke test: PASSED"
