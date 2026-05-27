"""Run inside router to repro updater failure."""
import sys
import traceback

sys.path.insert(0, "/opt/share/tgwsproxy")
from tgwsproxy.updater import _download_tarball, _extract_tarball
from pathlib import Path
import tempfile, shutil

url = "https://api.github.com/repos/Omn1z/tg-ws-keenetic/tarball/v1.1.3"
staging = Path("/opt/tmp/probe-update")
shutil.rmtree(staging, ignore_errors=True)
staging.mkdir(parents=True, exist_ok=True)
tarball = staging / "release.tar.gz"

try:
    print("downloading...")
    _download_tarball(url, tarball)
    print(f"download OK, size={tarball.stat().st_size}")
    print("extracting...")
    _extract_tarball(tarball, staging)
    print("extract OK; contents:")
    for p in sorted(staging.iterdir()):
        print(f"  {p.name}")
except Exception:
    traceback.print_exc()
