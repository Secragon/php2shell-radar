"""Download official PHP Windows builds for isolated localhost validation."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "php-lab"


def fetch(version):
    root = ROOT / version
    root.mkdir(parents=True, exist_ok=True)
    bases = [f"https://downloads.php.net/~windows/releases/archives/php-{version}-nts-Win32-{toolset}-x64.zip"
             for toolset in ("vs17", "vs16", "vc15")]
    archive = root / "php.zip"
    url = next((candidate for candidate in bases if (root / "provenance.json").exists() and
                json.loads((root / "provenance.json").read_text()).get("source") == candidate), bases[0])
    if not archive.exists():
        for candidate in bases:
            try:
                with urllib.request.urlopen(candidate, timeout=60) as response, archive.open("wb") as output:
                    while chunk := response.read(1024 * 1024):
                        output.write(chunk)
                url = candidate
                break
            except urllib.error.HTTPError as exc:
                if exc.code != 404 or candidate == bases[-1]:
                    raise
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            target = (root / item.filename).resolve()
            if not target.is_relative_to(root.resolve()):
                raise ValueError("Unsafe archive path")
        bundle.extractall(root)
    result = {"version": version, "source": url, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    (root / "provenance.json").write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=2) as pool:
        print(json.dumps(list(pool.map(fetch, sys.argv[1:] or ["8.4.26", "8.4.27"])), indent=2))
