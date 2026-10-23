"""Run offline tests and make failures visible in public CI annotations."""

import subprocess
import sys
import re


def main():
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        capture_output=True, text=True,
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    if result.returncode:
        names = re.findall(r"^(?:FAIL|ERROR): (test_[A-Za-z_0-9]+)", result.stderr, re.MULTILINE)
        types = re.findall(r"^([A-Za-z_0-9]+(?:Error|Exception)):", result.stderr, re.MULTILINE)
        libraries = re.findall(r"(lib[A-Za-z_0-9.-]+\.so(?:\.[0-9]+)*)", result.stderr)
        summary = ", ".join(sorted(set(names))) or "test suite import or setup"
        categories = ", ".join(sorted(set(types))) or "unknown error"
        dependencies = ", ".join(sorted(set(libraries)))
        if dependencies:
            categories += f"; missing library: {dependencies}"
        print(f"::error title=Offline test failure::{summary} ({categories})")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
