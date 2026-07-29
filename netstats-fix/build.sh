#!/bin/bash
set -euo pipefail; ROOT="$(cd "$(dirname "$0")" && pwd)"
NDK="${NDK:-$ROOT/../android-ndk-r27d}"
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
SRC="$ROOT/src/netproxy.c"
BIN="$ROOT/module/system/bin/netproxy"
echo "Compiling netproxy.c..."
"$CC" -O2 -Wall -o "$BIN" "$SRC"
echo "Binary size: $(stat -c%s "$BIN") bytes"
ZIP="$ROOT/netstats-fix-v9.zip"; rm -f "$ZIP"
cd "$ROOT/module" && zip -9 "$ZIP" module.prop customize.sh sepolicy.rule post-fs-data.sh service.sh system/bin/netproxy
echo "Done: $ZIP"
