#!/usr/bin/env bash
# Build dist/ramshift-<version>.pyz: the RAMShift modules plus their pure-Python
# dependencies (boto3, botocore, PyYAML and theirs), bundled as one executable zipapp.
#   packaging/build.sh            # uses python3 from PATH (3.11 or later)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
VERSION=$(sed -n 's/^TOOL_VERSION = "\(.*\)"$/\1/p' "$ROOT/src/ram_migration_common.py")
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT
mkdir -p "$BUILD/app/lib" "$ROOT/dist"
cp "$ROOT"/src/*.py "$BUILD/app/lib/"
"$PYTHON" -m pip install --quiet --no-compile --target "$BUILD/deps" -r "$ROOT/requirements.txt"
# Pure-Python only: compiled extensions cannot load from a zipapp; PyYAML falls back to Python.
(cd "$BUILD/deps" && find . -name "*.so" -delete && find . -name "__pycache__" -prune -exec rm -rf {} +)
for dist in "$BUILD"/deps/*.dist-info; do
  name=$(basename "$dist" .dist-info)
  for lic in "$dist"/licenses/* "$dist"/LICENSE* "$dist"/NOTICE*; do
    [ -f "$lic" ] && mkdir -p "$BUILD/app/lib/THIRD_PARTY_LICENSES/$name" && cp "$lic" "$BUILD/app/lib/THIRD_PARTY_LICENSES/$name/"
  done
done
find "$BUILD/deps" -maxdepth 1 -name "*.dist-info" -exec rm -rf {} +
cp -R "$BUILD"/deps/* "$BUILD/app/lib/"
(cd "$BUILD/app/lib" && find . -type f | LC_ALL=C sort | xargs shasum -a 256) | shasum -a 256 | cut -c1-16 > "$BUILD/app/BUILD_ID"
sed "s/^VERSION = \".*\"$/VERSION = \"$VERSION\"/" "$ROOT/packaging/launcher_main.py" > "$BUILD/app/__main__.py"
"$PYTHON" -m zipapp "$BUILD/app" -o "$ROOT/dist/ramshift-$VERSION.pyz" -p "/usr/bin/env python3" -c
chmod +x "$ROOT/dist/ramshift-$VERSION.pyz"
echo "$ROOT/dist/ramshift-$VERSION.pyz"
