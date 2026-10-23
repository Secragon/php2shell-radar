"""Confirm a packaged GUI starts and remains alive without network access."""

import os
from pathlib import Path
import subprocess
import sys
import time

import psutil


def bundle_processes(binary):
    """Include PyInstaller's separate GUI/extraction processes."""
    found = []
    for process in psutil.process_iter(["name", "exe"]):
        try:
            executable = process.info["exe"]
            same_path = executable and Path(executable).resolve() == binary
            same_name = (process.info["name"] or "").lower() == binary.name.lower()
            if same_path or same_name:
                found.append(process)
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue
    return found


def main():
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit(f"Missing bundle: {binary}")
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    existing = {member.pid for member in bundle_processes(binary)}
    process = psutil.Popen([str(binary)], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(8)
        if process.poll() is not None:
            raise SystemExit(f"GUI exited during startup: {process.returncode}")
        print(f"GUI startup passed: {binary.name}")
    finally:
        # PyInstaller onefile can leave GUI children after its parent exits.
        members = [member for member in bundle_processes(binary)
                   if member.pid not in existing]
        for member in members:
            try:
                member.terminate()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(members, timeout=10)
        for member in alive:
            member.kill()
        psutil.wait_procs(alive, timeout=10)
        remaining = [member.pid for member in bundle_processes(binary)
                     if member.pid not in existing]
        if remaining:
            raise SystemExit(f"GUI process remained after smoke test: {remaining}")


if __name__ == "__main__":
    main()
