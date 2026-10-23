"""Local-only check: is a PHP OOM response specific to an unpatched build?

Uses the request size/configuration from php-src's
sapi/cli/tests/oom_request_parsing_next_request.phpt. Never sends a request to
an external address. This is research evidence, not a production scanner.
"""

import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "php-lab"


def request(port, method, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(
            method, "/index.php", body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {},
        )
        response = conn.getresponse()
        content = response.read(4096).decode("utf-8", "replace")
        return {"status": response.status, "oom_fatal": "Allowed memory size of 8388608 bytes exhausted" in content,
                "alive_marker": "LAB_ALIVE" in content}
    except (OSError, http.client.HTTPException) as exc:
        return {"error": type(exc).__name__}
    finally:
        conn.close()


def check(version):
    with tempfile.TemporaryDirectory(prefix="php2shell-oom-lab-") as directory:
        web = Path(directory)
        (web / "index.php").write_text("<?php echo 'LAB_ALIVE';", encoding="utf-8")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            [str(ROOT / version / "php.exe"), "-n", "-d", "memory_limit=8M",
             "-d", "post_max_size=64M", "-d", "html_errors=0", "-d", "display_errors=1",
             "-S", f"127.0.0.1:{port}", "-t", str(web)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            for _ in range(50):
                baseline = request(port, "GET")
                if baseline.get("alive_marker"):
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError(f"Local PHP {version} did not start")
            body = b"a=" + b"a" * (6 * 1024 * 1024)
            triggered = request(port, "POST", body)
            next_request = request(port, "GET")
            return {"version": version, "baseline": baseline, "oom_request": triggered,
                    "next_request": next_request, "server_exited": process.poll() is not None}
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


def main():
    results = [check(version) for version in ("8.4.26", "8.4.27")]
    print(json.dumps(results, indent=2))
    output = ROOT / "oom-oracle.json"
    output.write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
