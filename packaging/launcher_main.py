"""RAMShift launcher: unpacks the bundled tool and its pure-Python dependencies once
into a per-user cache (botocore reads its service models from files), then runs it."""
import os
import sys
import tempfile
import zipfile
from pathlib import Path

VERSION = "0.0.0"
if sys.version_info < (3, 11):
    sys.exit(f"RAMShift {VERSION} requires Python 3.11 or later; this is {sys.version.split()[0]}")
archive = Path(__file__).resolve().parent
with zipfile.ZipFile(archive) as bundle:
    build = bundle.read("BUILD_ID").decode().strip()
    cache = Path(os.environ.get("RAMSHIFT_CACHE") or Path.home() / ".cache" / "ramshift")
    target = cache / f"{VERSION}-{build}"
    if not (target / ".complete").exists():
        cache.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".unpack-", dir=cache))
        for name in bundle.namelist():
            if name.startswith("lib/") and not name.endswith("/"):
                bundle.extract(name, staging)
        (staging / "lib" / ".complete").touch()
        try:
            (staging / "lib").rename(target)
        except OSError:  # another run unpacked it first
            pass
sys.path[:0] = [str(target)]

# The bundled application renders its readable console view (ram_migration_console)
# unless --raw-output asks for the technical event stream.
import temporary_migration_ram_shares as cli  # noqa: E402

sys.exit(cli.main(sys.argv[1:], readable=True))
