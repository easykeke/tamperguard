#!/usr/bin/env bash
# Build the Java RASP agent jar. Requires javac/jar (JDK 17+).
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 1
OUT=dist
mkdir -p "$OUT/classes"
javac -d "$OUT/classes" rasp/java/TamperGuardAgent.java
printf 'Premain-Class: TamperGuardAgent\nCan-Retransform-Classes: false\n' > "$OUT/manifest.txt"
jar --create --file "$OUT/tg-rasp.jar" --manifest "$OUT/manifest.txt" -C "$OUT/classes" .
echo "built $OUT/tg-rasp.jar"
