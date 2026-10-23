"""Compare a small session-warning probe on local official PHP builds only."""

import asyncio
import json
import re
import socket
import subprocess
import sys
from pathlib import Path

import httpx
from hunter.checker import collect_active_evidence, session_warning_shape
from hunter.engine import Control
from hunter.models import ScanOptions, Target
from hunter.network import Network
from hunter.network import Response


ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "php-lab"
WARNINGS = (
    "Session ID is too long or contains illegal characters",
    "Failed to read session data",
    "Failed to write session data",
)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def compare(version, display_errors, sid_source, upload_progress):
    folder = ROOT / version
    web = folder / "web"
    web.mkdir(exist_ok=True)
    (web / "index.php").write_text('<?php echo "Lab baseline";\n', encoding="utf-8")
    port = free_port()
    sid = "radar/invalid"
    command = [str(folder / "php.exe"), "-n", "-d", f"display_errors={int(display_errors)}",
               "-d", f"session.upload_progress.enabled={int(upload_progress)}", "-d", "session.use_strict_mode=0",
               "-d", f"session.save_path={folder}", "-S", f"127.0.0.1:{port}",
               "-t", str(web)]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            for _ in range(60):
                try:
                    await client.get(f"http://127.0.0.1:{port}/")
                    break
                except httpx.HTTPError:
                    await asyncio.sleep(0.05)
            else:
                raise RuntimeError(f"PHP {version} did not start")
            data = {"PHP_SESSION_UPLOAD_PROGRESS": "radar"}
            cookies = None
            if sid_source == "form":
                data["PHPSESSID"] = sid
            else:
                cookies = {"PHPSESSID": sid}
            response = await client.post(f"http://127.0.0.1:{port}/index.php", data=data,
                                         files={"f": ("x.txt", b"x", "text/plain")}, cookies=cookies)
        collector_status = None
        if display_errors and sid_source == "form" and upload_progress:
            url = f"http://127.0.0.1:{port}/index.php"
            scanner = Network(ScanOptions([Target("127.0.0.1", url)], interval=0, timeout=2), Control())
            try:
                baseline = await scanner.request("GET", url)
                active = await collect_active_evidence(scanner, url, baseline,
                                                       {"status": "INCONCLUSIVE", "reported_versions": []})
                collector_status = active["status"]
            finally:
                await scanner.close()
        plain = re.sub(r"<[^>]+>", " ", response.text)
        return {"version": version, "display_errors": display_errors, "sid_source": sid_source,
                "upload_progress": upload_progress,
                "http_status": response.status_code,
                "radar_shape": session_warning_shape(Response(str(response.url), response.status_code,
                                                                 dict(response.headers), response.text, 0)),
                "collector_status": collector_status,
                "warnings": {warning: warning in plain for warning in WARNINGS},
                "response_excerpt": " ".join(plain.split())[:900]}
    finally:
        process.terminate()
        process.wait(timeout=5)


async def main():
    rows = []
    quick = "--quick" in sys.argv
    versions = [arg for arg in sys.argv[1:] if arg != "--quick"] or ["8.4.26", "8.4.27"]
    for version in versions:
        for display_errors in ((True,) if quick else (True, False)):
            for sid_source in (("form",) if quick else ("form", "cookie")):
                for upload_progress in ((True,) if quick else (True, False)):
                    rows.append(await compare(version, display_errors, sid_source, upload_progress))
    fixed = {"8.2.35", "8.3.36", "8.4.27", "8.5.12"}
    for row in rows:
        flags = list(row["warnings"].values())
        visible = row["display_errors"] and row["upload_progress"]
        expected = ([False, False, False] if row["version"] == "7.4.33" or not visible else
                    [True, True, row["version"] not in fixed])
        assert flags == expected, row
        expected_shape = (("patched" if row["version"] in fixed else "unpatched")
                          if expected[0] and row["version"] != "8.1.34" else None)
        assert row["radar_shape"] == expected_shape, row
        if row["collector_status"] is not None:
            expected_status = ("NO_OOM_OBSERVED" if row["version"] in {"7.4.33", "8.1.34"} else
                               "PATCHED_SESSION_PATH" if row["version"] in fixed else "UNPATCHED_SESSION_PATH")
            assert row["collector_status"] == expected_status, row
    output = ROOT / "session-warning-oracle.json"
    output.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
