#!/bin/bash
set -euo pipefail; ROOT="$(cd "$(dirname "$0")" && pwd)"
JDK_HOME="${JDK_HOME:-}"; if [ -z "$JDK_HOME" ]; then for d in /usr/lib/jvm/java-17-openjdk* /usr/lib/jvm/java-21-openjdk*; do [ -f "$d/bin/javac" ] && { JDK_HOME="$d"; break; }; done; fi
[ -z "$JDK_HOME" ] && { echo "JDK 17+ not found"; exit 1; }; echo "JDK: $JDK_HOME"
R8_JAR="${R8_JAR:-}"; if [ -z "$R8_JAR" ]; then for f in "$ROOT/r8lib.jar" "$ROOT/libs/r8lib.jar" "$HOME/.cache/Flint/r8lib.jar"; do [ -f "$f" ] && { R8_JAR="$f"; break; }; done; fi
if [ -z "$R8_JAR" ]; then R8_JAR="$ROOT/r8lib.jar"; echo "Downloading r8..."; curl -fSL -o "$R8_JAR" "https://storage.googleapis.com/r8-releases/raw/main/com/android/tools/r8/r8/9.1.31/r8-9.1.31.jar"; fi
[ ! -f "$R8_JAR" ] && { echo "r8 not found"; exit 1; }
BD="$ROOT/build"; rm -rf "$BD"; mkdir -p "$BD/classes"
echo "Compiling..."; "$JDK_HOME/bin/javac" --release 17 -d "$BD/classes" -sourcepath "$ROOT/src:$ROOT/stubs" "$ROOT/src/com/flint/netstats/NetworkStatsProxy.java"
echo "D8..."; "$JDK_HOME/bin/java" -cp "$R8_JAR" com.android.tools.r8.D8 --release --min-api 34 --output "$BD/proxy_out.zip" "$BD/classes/com/flint/netstats/NetworkStatsProxy.class"
unzip -o -d "$BD" "$BD/proxy_out.zip" classes.dex; cp "$BD/classes.dex" "$ROOT/module/proxy.dex"
ZIP="$ROOT/netstats-fix-v8.zip"; rm -f "$ZIP"
(cd "$ROOT/module" && zip -9 "$ZIP" module.prop customize.sh sepolicy.rule post-fs-data.sh service.sh proxy.dex system/lib64/libbinder_pool.so)
echo "Done: $ZIP"
