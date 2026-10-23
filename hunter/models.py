from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


CVES = ("CVE-2026-109618", "CVE-2026-109619")
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
ADVISORIES = [
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
]
WEB_PORTS = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9000)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Target:
    host: str
    url: str | None = None


def parse_targets(text: str) -> list[Target]:
    targets = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        explicit = "://" in line
        parsed = urlsplit(line if explicit else "//" + line)
        if explicit and parsed.scheme not in ("http", "https"):
            raise ValueError(f"Unsupported protocol: {line}")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs with credentials are not supported.")
        if not parsed.hostname:
            raise ValueError(f"Missing hostname: {line}")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in host.split(".")):
                raise ValueError(f"Invalid hostname: {host}")
        port = parsed.port  # validates range
        if not explicit and (parsed.path not in ("", "/") or parsed.query):
            raise ValueError(f"Include http:// or https:// for a path: {line}")
        url = None
        if explicit or port:
            scheme = parsed.scheme if explicit else ("https" if port in (443, 8443) else "http")
            authority = f"[{host}]" if ":" in host else host
            if port:
                authority += f":{port}"
            url = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))
        target = Target(host, url)
        targets[(host, url)] = target
    if not targets:
        raise ValueError("Enter at least one domain or URL.")
    return list(targets.values())


@dataclass
class ScanOptions:
    targets: list[Target]
    passive_dns: bool = False
    active_dns: bool = False
    extra_ports: bool = False
    ports: list[int] = field(default_factory=lambda: list(WEB_PORTS))
    words: list[str] = field(default_factory=list)
    active_check: bool = False
    collect_patch_evidence: bool = False
    concurrency: int = 8
    timeout: float = 7.0
    interval: float = 0.35
    verify_tls: bool = True
    crawl: bool = False
    max_pages: int = 12
    recursive_dns: bool = False
    ct_pages: int = 50
    tls_names: bool = False
    all_addresses: bool = False

    def to_dict(self):
        return asdict(self)


def endpoints(target: Target, options: ScanOptions) -> list[str]:
    host = f"[{target.host}]" if ":" in target.host else target.host
    result = [target.url] if target.url else [f"https://{host}/", f"http://{host}/"]
    if options.extra_ports:
        for port in options.ports:
            schemes = ("https",) if port == 443 else ("http",) if port == 80 else ("http", "https")
            result.extend(f"{scheme}://{host}:{port}/" for scheme in schemes)
    normalized = {}
    for url in result:
        p = urlsplit(url)
        port = p.port or (443 if p.scheme == "https" else 80)
        normalized[(p.scheme, p.hostname, port, p.path, p.query)] = url
    return list(normalized.values())


def version_assessment(version: str | None) -> dict:
    """HTTP banners are evidence, never authenticated patch verification."""
    result = {"status": "UNKNOWN", "reason": "No trustworthy runtime/build inventory available."}
    if not version:
        return result
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", version)
    if not match:
        return result
    major, minor, patch = map(int, match.groups()[:3])
    suffix = match.group(4)
    if suffix:
        return {"status": "BUILD_VERIFICATION_REQUIRED", "reason": "Vendor/prerelease build: compare the complete package revision with its vendor advisory."}
    branch = (major, minor)
    if branch in FIXED:
        if patch >= FIXED[branch]:
            return {"status": "FIXED_VERSION_REPORTED", "reason": "HTTP reports an upstream fixed version; verify the deployed runtime and workers."}
        return {"status": "POTENTIALLY_AFFECTED", "reason": "Reported version predates the upstream fix. Vendor backports may apply."}
    if (5, 4) <= branch < (8, 2):
        return {"status": "POTENTIALLY_AFFECTED", "reason": "Legacy PHP branch: verify vendor backports, including source backports for 7.4/8.0/8.1."}
    return result


def triage_assessment(asset: dict) -> tuple[str, str]:
    """Combine reported versions with a repeated, patch-specific session-path result."""
    active = asset.get("active") or {}
    patch = asset.get("patch_evidence") or active.get("patch_evidence") or {}
    if active.get("status") == "UNPATCHED_SESSION_PATH":
        if asset.get("assessment") == "FIXED_VERSION_REPORTED" or patch.get("status") == "PATCH_FEATURE_OBSERVED":
            return "Unconfirmed", "The active session-path result conflicts with reported patch evidence; check the actual PHP workers."
        return "Vulnerable", ("Two active requests reproduced PHP session behavior present before the security fix "
                              "and absent from matched fixed releases. This confirms an unpatched code path, not code execution.")
    if asset.get("php") != "DETECTED":
        return "Unconfirmed", "PHP runtime is not established."
    if asset.get("wildcard_ambiguous"):
        return "Unconfirmed", "Wildcard DNS makes this hostname's backend identity uncertain."
    status = asset.get("assessment")
    if status == "POTENTIALLY_AFFECTED":
        if patch.get("status") == "PATCH_FEATURE_OBSERVED" or active.get("status") == "PATCHED_SESSION_PATH":
            return "Unconfirmed", "An older reported version also shows post-fix behavior; check vendor backports."
        return "At risk", "The endpoint reports a PHP version below the upstream fix. Backports and the actual runtime still require verification."
    if asset.get("detection_partial"):
        return "Unconfirmed", "The partial response does not establish the PHP patch level."
    if asset.get("proxy"):
        return "Unconfirmed", "An edge proxy may obscure the PHP runtime being assessed."
    if status == "FIXED_VERSION_REPORTED":
        return "Fixed version", "The endpoint reports an upstream fixed PHP version; verify the deployed build and workers."
    return "Unconfirmed", "Available HTTP evidence does not establish the PHP patch level."


def passive_decisive(asset: dict) -> bool:
    """Skip opt-in active traffic only for an unambiguous fixed upstream build."""
    verdict, _ = triage_assessment(asset)
    version = asset.get("version")
    if verdict != "Fixed version" or not version:
        return False
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match or tuple(map(int, match.groups()[:2])) not in FIXED:
        return False
    if asset.get("reported_versions") != [version]:
        return False
    status = asset.get("http_status", 0)
    return 200 <= status < 400
