"""Compare diagnostics on official PHP; no memory corruption or RCE payloads."""
import asyncio
import json
from pathlib import Path
import socket
import subprocess
import time
import urllib.request

from hunter.checker import collect_active_evidence, collect_patch_evidence
from hunter.engine import Control
from hunter.models import ScanOptions, Target
from hunter.network import Network

ROOT = Path(__file__).resolve().parents[1] / "artifacts" / "php-lab"


async def check(url):
    options = ScanOptions([Target("127.0.0.1", url)], interval=0.05)
    network = Network(options, Control())
    try:
        baseline = await network.request("GET", url)
        result = await collect_patch_evidence(network, url, baseline)
        active = await collect_active_evidence(network, url, baseline)
        info = await network.request("GET", url + "info.php")
        marker = "memory_hard_limit_percent" in info.text
        # Lab-only reproduction of the REJECTED probe, never a production verdict.
        boundary = "HunterValidation"
        def body(sid):
            return (f'--{boundary}\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
                    f'--{boundary}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nhunter\r\n'
                    f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="test.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n--{boundary}--\r\n').encode()
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}", "Cookie": ""}
        control = await network.request("POST", url, headers=headers, content=body("huntervalidation"))
        probe = await network.request("POST", url, headers=headers, content=body("huntervalidation/"))
        warning = "Session ID is too long or contains illegal characters"
        return {"diagnostic": result, "active": active, "hard_limit_marker": marker,
                "patch_feature_detected": result["status"] == "PATCH_FEATURE_OBSERVED",
                "rejected_session_probe_positive": warning in probe.text and warning not in control.text}
    finally:
        await network.close()


def main():
    results = []
    for version in ("8.4.26", "8.4.27"):
        root = ROOT / version
        web = root / "web"
        web.mkdir(exist_ok=True)
        (web / "index.php").write_text("<?php echo 'Lab baseline';")
        (web / "info.php").write_text("<?php phpinfo(INFO_GENERAL | INFO_CONFIGURATION);")
        for display in (0, 1):
            for progress in (0, 1):
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
                command = [str(root / "php.exe"), "-n", "-d", f"display_errors={display}",
                           "-d", f"session.upload_progress.enabled={progress}",
                           "-d", f"session.save_path={root}", "-S", f"127.0.0.1:{port}", "-t", str(web)]
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                try:
                    url = f"http://127.0.0.1:{port}/"
                    for _ in range(50):
                        try:
                            urllib.request.urlopen(url, timeout=0.2).close()
                            break
                        except OSError:
                            time.sleep(0.05)
                    result = asyncio.run(check(url))
                    assert result["patch_feature_detected"] == (version == "8.4.27"), result
                    assert result["diagnostic"]["reported_versions"] == [version], result
                    assert set(result["diagnostic"]["cves"].values()) == {"NOT_CONFIRMED"}
                    assert set(result["active"]["cves"].values()) == {"NOT_CONFIRMED"}
                    assert result["active"]["status"] in {"NO_OOM_OBSERVED", "OOM_OBSERVED", "INCONCLUSIVE"}, result
                    assert 1 <= len(result["active"]["evidence"]) <= 2, result
                    assert all(item["request_bytes"] <= 2_600_000 for item in result["active"]["evidence"]), result
                    assert "recovery" in result["active"], result
                    assert result["rejected_session_probe_positive"] == bool(display and progress), result
                    results.append({"version": version, "display_errors": display, "upload_progress": progress, **result})
                finally:
                    process.terminate()
                    process.wait(timeout=5)
    path = ROOT / "validation.json"
    path.write_text(json.dumps(results, indent=2))
    print(json.dumps([{key: row[key] for key in ("version", "display_errors", "upload_progress", "patch_feature_detected", "rejected_session_probe_positive")} for row in results], indent=2))


if __name__ == "__main__":
    main()
