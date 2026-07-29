#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

# --- Locate JDK ---
JDK_HOME="${JDK_HOME:-}"
if [ -z "$JDK_HOME" ]; then
    for d in /usr/lib/jvm/java-17-openjdk* /usr/lib/jvm/java-21-openjdk* /usr/lib/jvm/java-24-openjdk* /usr/lib/jvm/default-java /usr/lib/jvm/jdk-17* /usr/lib/jvm/jdk-21* /usr/lib/jvm/jdk-24*; do
        if [ -f "$d/bin/javac" ]; then JDK_HOME="$d"; break; fi
    done
fi
if [ -z "$JDK_HOME" ]; then echo "JDK 17+ not found. Set JDK_HOME."; exit 1; fi
echo "JDK: $JDK_HOME"

# --- Locate / download r8 ---
R8_JAR="${R8_JAR:-}"
if [ -z "$R8_JAR" ]; then
    for f in "$ROOT/r8lib.jar" "$ROOT/libs/r8lib.jar" "$HOME/.cache/opencode/r8lib.jar"; do
        if [ -f "$f" ]; then R8_JAR="$f"; break; fi
    done
fi
if [ -z "$R8_JAR" ]; then
    R8_JAR="$ROOT/r8lib.jar"
    R8_URL="https://storage.googleapis.com/r8-releases/raw/main/com/android/tools/r8/r8/9.1.31/r8-9.1.31.jar"
    echo "Downloading r8 from $R8_URL ..."
    curl -fSL -o "$R8_JAR" "$R8_URL"
fi
if [ ! -f "$R8_JAR" ]; then echo "r8 JAR not found at $R8_JAR"; exit 1; fi

BUILD_DIR="$ROOT/build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/classes"

SRC="$ROOT/src"
STUBS="$ROOT/stubs"
MODULE="$ROOT/module"

echo "Compiling..."
"$JDK_HOME/bin/javac" --release 17 -d "$BUILD_DIR/classes" -sourcepath "$SRC:$STUBS" "$SRC/com/opencode/netstats/NetworkStatsProxy.java"

echo "Converting to DEX..."
"$JDK_HOME/bin/java" -cp "$R8_JAR" com.android.tools.r8.D8 --release --min-api 34 --output "$BUILD_DIR/proxy_out.zip" "$BUILD_DIR/classes/com/opencode/netstats/NetworkStatsProxy.class"

# Extract classes.dex
unzip -o -d "$BUILD_DIR" "$BUILD_DIR/proxy_out.zip" classes.dex
cp "$BUILD_DIR/classes.dex" "$MODULE/proxy.dex"

# Package module zip
OUTPUT_ZIP="$ROOT/netstats-fix-v7.zip"
rm -f "$OUTPUT_ZIP"
(cd "$MODULE" && zip -9 -r "$OUTPUT_ZIP" module.prop customize.sh sepolicy.rule post-fs-data.sh service.sh proxy.dex)

echo "Done: $OUTPUT_ZIP ($(stat -c%s "$OUTPUT_ZIP" 2>/dev/null || echo "?") bytes)"
