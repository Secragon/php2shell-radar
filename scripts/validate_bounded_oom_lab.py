"""Run production-sized multipart probes only against local official PHP builds."""

import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from hunter.checker import multipart_probe


ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "php-lab"


def request(port, method, headers=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request(method, "/index.php", body=body, headers=headers or {})
        response = connection.getresponse()
        content = response.read(4096).decode("utf-8", "replace")
        return {"status": response.status, "oom_text": "Allowed memory size" in content,
                "alive_marker": "LAB_ALIVE" in content}
    except (OSError, http.client.HTTPException) as exc:
        return {"error": type(exc).__name__}
    finally:
        connection.close()


def check(version, method):
    with tempfile.TemporaryDirectory(prefix="php2shell-bounded-lab-") as directory:
        web = Path(directory)
        (web / "index.php").write_text("<?php echo 'LAB_ALIVE';", encoding="utf-8")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(
            [str(ROOT / version / "php.exe"), "-n", "-d", "memory_limit=4M",
             "-d", "post_max_size=64M", "-d", "html_errors=0", "-d", "display_errors=1",
             "-d", "session.upload_progress.enabled=1", "-d", "session.upload_progress.freq=1",
             "-d", "session.upload_progress.min_freq=0", "-d", "session.upload_progress.cleanup=0",
             "-d", f"session.save_path={directory}",
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
            headers, body = multipart_probe(method, "0123456789abcdef")
            triggered = request(port, "POST", headers, body)
            recovery = request(port, "GET")
            return {"version": version, "method": method, "request_bytes": len(body),
                    "baseline": baseline, "probe": triggered, "recovery": recovery,
                    "session_file_count": len(list(web.glob("sess_*"))),
                    "server_exited": process.poll() is not None}
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


def main():
    results = [check(version, method) for version in ("8.4.26", "8.4.27")
               for method in ("part_headers", "nested_empty_files", "session_upload_progress")]
    print(json.dumps(results, indent=2))
    (ROOT / "bounded-oom-lab.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
