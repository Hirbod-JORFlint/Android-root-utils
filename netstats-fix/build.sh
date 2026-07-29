#!/bin/bash
# Build script for Network Stats Fix module
# Requires Android NDK r27+ in $NDK or ../ims/android-ndk-r27c

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/src"
MOD="$SCRIPT_DIR/module"
OUT="$SCRIPT_DIR"

# Find NDK
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

# Clean old binary
rm -f "$MOD/system/bin/netproxy" "$MOD/system/bin/netproxy_arm"
mkdir -p "$MOD/system/bin"

# Compile ARM64
echo "Compiling ARM64..."
"$TOOLCHAIN/bin/aarch64-linux-android21-clang" \
    -o "$MOD/system/bin/netproxy" \
    -O2 -s -static "$SRC/netproxy.c"
if [ $? -eq 0 ] && [ -f "$MOD/system/bin/netproxy" ]; then
    echo "  ARM64: $(stat -c%s "$MOD/system/bin/netproxy") bytes"
else
    echo "  ARM64 FAILED!"
    exit 1
fi

# Compile ARM32
echo "Compiling ARM32..."
"$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang" \
    -o "$MOD/system/bin/netproxy_arm" \
    -O2 -s -static "$SRC/netproxy.c"
if [ $? -eq 0 ] && [ -f "$MOD/system/bin/netproxy_arm" ]; then
    echo "  ARM32: $(stat -c%s "$MOD/system/bin/netproxy_arm") bytes"
else
    echo "  ARM32 FAILED!"
    exit 1
fi

# Build full module zip
echo "Building full module..."
cd "$MOD"
FULL_ZIP="$OUT/netstats-fix-v10.zip"
rm -f "$FULL_ZIP"
zip -r9 "$FULL_ZIP" . -x "*.git*" "*.sh" "*_lite.*" "system/bin/netproxy_arm"
echo "  Created: $FULL_ZIP"

# Build lite module zip (no BPF, proxy only)
echo "Building lite module..."
LITE_ZIP="$OUT/netstats-fix-v10-lite.zip"
rm -f "$LITE_ZIP"
# Use full contents but with lite scripts
cp "$MOD/service_lite.sh" "$MOD/service.sh"
cp "$MOD/post-fs-data_lite.sh" "$MOD/post-fs-data.sh"
cp "$MOD/module_lite.prop" "$MOD/module.prop"
zip -r9 "$LITE_ZIP" . -x "*.git*" "*.sh" "system/bin/netproxy_arm"
echo "  Created: $LITE_ZIP"

# Restore full scripts
git checkout -- "$MOD/service.sh" "$MOD/post-fs-data.sh" "$MOD/module.prop" 2>/dev/null || \
    cp "$MOD/service.sh" "$MOD/service.sh.bak" 2>/dev/null || true

echo ""
echo "Done! Modules built:"
echo "  $FULL_ZIP"
echo "  $LITE_ZIP"
