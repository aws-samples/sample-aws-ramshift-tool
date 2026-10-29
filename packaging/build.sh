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
# The bundled third-party distributions, their versions and licenses, for the release notes.
"$PYTHON" - "$BUILD/deps" > "$ROOT/dist/THIRD-PARTY-LICENSES.md" <<'PY'
import sys
from email.parser import Parser
from pathlib import Path
rows = []
for meta in sorted(Path(sys.argv[1]).glob("*.dist-info/METADATA")):
    m = Parser().parsestr(meta.read_text(encoding="utf-8"))
    license_ = m.get("License-Expression") or next(
        (c.split("::")[-1].strip() for c in m.get_all("Classifier") or [] if c.startswith("License ::")),
        None) or (m.get("License") or "see bundled license file").splitlines()[0]
    rows.append(f"| {m['Name']} | {m['Version']} | {license_} | {m.get('Home-page') or ''} |")
print("# Third-party software bundled in ramshift-<version>.pyz\n")
print("The executable bundles these Python distributions unmodified. Each one's license and")
print("notice files are inside it under lib/THIRD_PARTY_LICENSES/.\n")
print("| Distribution | Version | License | Home page |\n|---|---|---|---|")
print("\n".join(rows))
PY
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
(cd "$ROOT/dist" && shasum -a 256 "ramshift-$VERSION.pyz" THIRD-PARTY-LICENSES.md > SHA256SUMS)
echo "$ROOT/dist/ramshift-$VERSION.pyz"
