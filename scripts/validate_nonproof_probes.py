"""Local-only comparison of two claimed PHP2Shell observables on real PHP builds.

Uses small multipart requests. Never sends attacker PHP or memory-pressure bodies.
No remote target argument is accepted.
"""
import asyncio
import json
import socket
import subprocess
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "php-lab"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def compare(version):
    folder = ROOT / version
    if not (folder / "php.exe").exists():
        raise FileNotFoundError(f"Run scripts/fetch_php_lab.py first: {version}")
    port = free_port()
    sid = "hunter" + uuid.uuid4().hex[:20]
    base = f"http://127.0.0.1:{port}/"
    command = [str(folder / "php.exe"), "-n", "-d", "display_errors=1",
               "-d", "session.upload_progress.enabled=1",
               "-d", "session.upload_progress.cleanup=0",
               "-d", "session.use_only_cookies=1",
               "-d", f"session.save_path={folder}", "-S",
               f"127.0.0.1:{port}", "-t", str(folder / "web")]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    session_file = folder / f"sess_{sid}"
    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            for _ in range(50):
                try:
                    await client.get(base)
                    break
                except httpx.HTTPError:
                    await asyncio.sleep(0.05)
            else:
                raise RuntimeError(f"Local PHP server did not start: {version}")
            invalid = await client.post(
                base, data={"PHPSESSID": "hunter/invalid",
                            "PHP_SESSION_UPLOAD_PROGRESS": "hunterlab"},
                files={"file": ("x.txt", b"X", "text/plain")})
            progress = await client.post(
                base, data={"PHP_SESSION_UPLOAD_PROGRESS": "hunterlab"},
                files={"file": ("x.txt", b"X", "text/plain")},
                cookies={"PHPSESSID": sid})
        return {"version": version,
                "invalid_sid_warning": "Session ID is too long or contains illegal characters" in invalid.text,
                "invalid_sid_status": invalid.status_code,
                "normal_progress_status": progress.status_code,
                "progress_file_created": session_file.exists(),
                "marker_present": b"hunterlab" in session_file.read_bytes() if session_file.exists() else False}
    finally:
        process.terminate()
        process.wait(timeout=5)
        if session_file.exists():
            session_file.unlink()


async def main():
    rows = [await compare(version) for version in ("8.4.26", "8.4.27")]
    assert all(row["invalid_sid_warning"] for row in rows), rows
    assert all(row["marker_present"] for row in rows), rows
    (ROOT / "nonproof-probes.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
