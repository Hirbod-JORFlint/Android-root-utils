#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/src"
MOD="$SCRIPT_DIR/module"
OUT="$SCRIPT_DIR"

if [ -z "$NDK" ]; then
    if [ -d "$SCRIPT_DIR/../ims/android-ndk-r27c" ]; then
        NDK="$SCRIPT_DIR/../ims/android-ndk-r27c"
    else
        echo "ERROR: NDK not found. Set NDK environment variable."
        exit 1
    fi
fi

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
[ -d "$TOOLCHAIN" ] || TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/windows-x86_64"
[ -d "$TOOLCHAIN" ] || TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64"

if [ ! -d "$TOOLCHAIN" ]; then
    echo "ERROR: NDK toolchain not found at $TOOLCHAIN"
    exit 1
fi

echo "Using NDK: $NDK"
echo "Toolchain: $TOOLCHAIN"

rm -f "$MOD/system/bin/netproxy" "$MOD/system/bin/netproxy_arm"
mkdir -p "$MOD/system/bin"

echo "Compiling ARM64..."
"$TOOLCHAIN/bin/aarch64-linux-android21-clang" \
    -o "$MOD/system/bin/netproxy" \
    -O2 -s -fPIE -pie "$SRC/netproxy.c"
if [ $? -eq 0 ] && [ -f "$MOD/system/bin/netproxy" ]; then
    echo "  ARM64: $(stat -c%s "$MOD/system/bin/netproxy") bytes"
else
    echo "  ARM64 FAILED!"
    exit 1
fi

echo "Compiling ARM32..."
"$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang" \
    -o "$MOD/system/bin/netproxy_arm" \
    -O2 -s -fPIE -pie "$SRC/netproxy.c"
if [ $? -eq 0 ] && [ -f "$MOD/system/bin/netproxy_arm" ]; then
    echo "  ARM32: $(stat -c%s "$MOD/system/bin/netproxy_arm") bytes"
else
    echo "  ARM32 FAILED!"
    exit 1
fi

# Build full module zip
echo "Building full module..."
FULL_TMP=$(mktemp -d)
cp -r "$MOD/"* "$FULL_TMP/"
rm -f "$FULL_TMP/service_lite.sh" "$FULL_TMP/post-fs-data_lite.sh" "$FULL_TMP/module_lite.prop"
cd "$FULL_TMP"
FULL_ZIP="$OUT/netstats-fix-v14.zip"
rm -f "$FULL_ZIP"
find . -type f | sed 's|^\./||' | sort | zip -r9 -@ "$FULL_ZIP"
echo "  Created: $FULL_ZIP"
cd "$SCRIPT_DIR"
rm -rf "$FULL_TMP"

# Build lite module zip
echo "Building lite module..."
LITE_TMP=$(mktemp -d)
cp -r "$MOD/"* "$LITE_TMP/"
rm -f "$LITE_TMP/service.sh" "$LITE_TMP/post-fs-data.sh" "$LITE_TMP/module.prop"
mv "$LITE_TMP/service_lite.sh" "$LITE_TMP/service.sh"
mv "$LITE_TMP/post-fs-data_lite.sh" "$LITE_TMP/post-fs-data.sh"
mv "$LITE_TMP/module_lite.prop" "$LITE_TMP/module.prop"
cd "$LITE_TMP"
LITE_ZIP="$OUT/netstats-fix-v14-lite.zip"
rm -f "$LITE_ZIP"
find . -type f | sed 's|^\./||' | sort | zip -r9 -@ "$LITE_ZIP"
echo "  Created: $LITE_ZIP"
cd "$SCRIPT_DIR"
rm -rf "$LITE_TMP"

echo ""
echo "Done! Modules built:"
echo "  $FULL_ZIP"
echo "  $LITE_ZIP"
