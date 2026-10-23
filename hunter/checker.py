"""Patch-specific session behavior and bounded PHP2Shell exposure checks.

A single invalid-SID warning occurs on both sides of the fix. Only the
additional session-write warning, reproduced on matched PHP builds, is used
as evidence of the pre-fix path. Neither signature proves code execution.
"""
from html.parser import HTMLParser
from html import unescape
import re
import secrets
from urllib.parse import urljoin

from hunter.models import ADVISORIES, CVES
from hunter.network import Stopped


MAX_PROBE_BYTES = 2_600_000
OOM_TEXT = re.compile(r"(?:Allowed memory size of \d+ bytes exhausted|Out of memory \(allocated \d+ bytes\))", re.I)
SESSION_COOKIE = re.compile(r"(?:^|[,\r\n]\s*)PHPSESSID=([^;,\r\n]*)", re.I)
LARGE_SESSION_COOKIE = 1024


def php_session_cookie_length(headers):
    """Return only the longest PHPSESSID length; never expose its value."""
    raw = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
    lengths = [match.end(1) - match.start(1) for match in SESSION_COOKIE.finditer(raw)]
    return max(lengths, default=None)


def unusual_cookie_length(length, baseline_length):
    return (length is not None and length >= LARGE_SESSION_COOKIE
            and length >= (baseline_length or 0) + 512)


def multipart_probe(method, token):
    """Three bounded vendor-described multipart pressure mechanisms, without PHP code.

    The fixed upper bound is intentionally far below the unbounded public PoCs.
    A completed or failed request is not a CVE-specific oracle.
    """
    boundary = "Hunter" + token
    if method == "part_headers":
        # Multipart *part* headers, not oversized HTTP headers.  The parser
        # allocates per-header state during rfc1867 request startup.
        header = b"X-Hunter-Padding: " + b"a" * 480 + b"\r\n"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n".encode()
                + header * 4600 + b"Content-Type: text/plain\r\n\r\nx\r\n"
                + f"--{boundary}--\r\n".encode())
    elif method == "nested_empty_files":
        # The official advisory identifies nested names on empty file controls
        # as a distinct memory-amplification route through the same parser.
        prefix = f"--{boundary}\r\nContent-Disposition: form-data; name=\"hunter[".encode()
        suffix = ("[a]" * 30 + ']"; filename=""\r\n'
                  "Content-Type: application/octet-stream\r\n\r\n\r\n").encode()
        body = b"".join(prefix + f"{index:04d}".encode() + suffix for index in range(10000))
        body += f"--{boundary}--\r\n".encode()
    elif method == "session_upload_progress":
        # PHP's upload-progress handler repeatedly updates session state as
        # file parts arrive. A fresh form SID avoids touching an existing user
        # session. This is the non-disclosing trigger from the vendor test,
        # not the later forged-memory or RCE stages of public exploit chains.
        start = f"--{boundary}\r\n".encode()
        body = (start + b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
                + token.encode() + b"\r\n"
                + start + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                + b"radar\r\n")
        body += b"".join(
            start + f'Content-Disposition: form-data; name="u{index}"; filename="f{index}.txt"\r\n'.encode()
            + b"Content-Type: text/plain\r\n\r\nx\r\n"
            for index in range(4000)
        )
        body += f"--{boundary}--\r\n".encode()
    else:
        raise ValueError("Unknown multipart probe")
    if len(body) > MAX_PROBE_BYTES:
        raise ValueError("Multipart probe exceeded the size cap")
    return {"Content-Type": f"multipart/form-data; boundary={boundary}"}, body


SESSION_WARNING_PHRASES = (
    "Session ID is too long or contains illegal characters",
    "Failed to read session data",
    "Failed to write session data",
)


def session_warning_probe(token):
    """Small invalid-session request; it cannot create a valid session file."""
    boundary = "Radar" + token
    sid = "radar/" + token
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nradar\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="f"; filename="r.txt"\r\n'
        f'Content-Type: text/plain\r\n\r\nx\r\n--{boundary}--\r\n'
    ).encode("ascii")
    return {"Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"PHPSESSID={sid}"}, body


def session_warning_shape(response):
    """Recognize PHP's startup warnings without retaining response content."""
    if response.truncated or not 200 <= response.status < 300:
        return None
    plain = " ".join(unescape(re.sub(r"<[^>]{0,200}>", " ", response.text)).split())
    positions = [plain.find("PHP Request Startup: " + phrase) for phrase in SESSION_WARNING_PHRASES]
    if positions[0] < 0 or positions[1] < positions[0]:
        return None
    return "unpatched" if positions[2] > positions[1] else "patched"


class InfoParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows, self.row, self.cell = [], None, None
        self.headings, self.heading = [], None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        if tag in ("td", "th") and self.row is not None:
            self.cell = []
        if tag in ("h1", "h2"):
            self.heading = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)
        if self.heading is not None:
            self.heading.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append("".join(self.cell).strip())
            self.cell = None
        if tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row = None
        if tag in ("h1", "h2") and self.heading is not None:
            self.headings.append("".join(self.heading).strip())
            self.heading = None


def patch_evidence(response):
    if response.status != 200 or response.truncated:
        return None
    text = response.text
    if not ("phpinfo()" in text.lower() and "PHP Version" in text and "Configuration" in text):
        return None
    parser = InfoParser()
    parser.feed(text)
    versions = [match.group(1) for heading in parser.headings
                if (match := re.fullmatch(r"PHP Version\s+(\d+\.\d+\.\d+(?:[-+~.a-zA-Z0-9]*)?)", heading, re.I))]
    settings = {}
    allowed = {"memory_hard_limit_percent", "memory_limit", "session.upload_progress.enabled", "fatal_error_backtraces"}
    for row in parser.rows:
        if len(row) >= 3 and row[0] in allowed:
            settings[row[0]] = row[1:3]
    hard = settings.get("memory_hard_limit_percent")
    marker = bool(hard and all(re.fullmatch(r"-?\d+|no value", v, re.I) for v in hard))
    return {"url": response.url, "type": "phpinfo_patch_feature", "settings": settings,
            "reported_version": versions[0] if len(set(versions)) == 1 and versions else None,
            "oom_patch_feature": marker,
            "interpretation": "OOM patch feature is reported; not proof of a complete vendor patch or of all running workers." if marker else "Feature not observed; absence does not prove vulnerability."}


async def collect_patch_evidence(network, url, baseline):
    """Read-only HTTP collection: no supplied PHP, POST or memory trigger."""
    result = {"status": "INCONCLUSIVE", "mode": "PATCH_EVIDENCE_ONLY",
              "reason": "No validated code-free remote test of the memory-corruption defect is available in this build.",
              "cves": {c: "NOT_CONFIRMED" for c in CVES}, "evidence": [], "sources": ADVISORIES}
    observed, responses = set(), [baseline]
    for path in ("phpinfo.php", "info.php"):
        candidate = urljoin(url, path)
        if candidate == baseline.url:
            continue
        try:
            response = await network.request("GET", candidate, follow=False, limit=512000)
            responses.append(response)
            if response.status == 429:
                break
        except Stopped:
            raise
        except Exception as exc:
            result.setdefault("request_errors", []).append({"url": candidate, "error": type(exc).__name__})
    for response in responses:
        evidence = patch_evidence(response)
        if evidence and response.url not in observed:
            observed.add(response.url)
            result["evidence"].append(evidence)
    result["reported_versions"] = sorted({e["reported_version"] for e in result["evidence"] if e["reported_version"]})
    if any(e["oom_patch_feature"] for e in result["evidence"]):
        result["status"] = "PATCH_FEATURE_OBSERVED"
        result["reason"] = "Read-only evidence of the OOM fix feature. CVE exploitability and completeness of the stale-state fix remain unconfirmed."
    return result


async def collect_active_evidence(network, url, baseline, patch_result=None,
                                  wordpress_login=False, allow_oom=True):
    """Check the patched session path, then run bounded OOM observations if unclear.

    Even a literal PHP OOM is not evidence of the vulnerable post-bailout state:
    patched PHP can produce the same fatal error. Stop on any rejection or
    anomalous response to avoid repeated pressure on an unhealthy service.
    """
    result = {"status": "INCONCLUSIVE", "mode": "BOUNDED_OOM",
              "reason": "Active HTTP responses cannot establish whether this PHP build has either CVE.",
              "cves": {c: "NOT_CONFIRMED" for c in CVES}, "evidence": [], "sources": ADVISORIES}
    baseline_cookie_length = php_session_cookie_length(baseline.headers)
    if baseline_cookie_length is not None:
        result["baseline_php_session_cookie_length"] = baseline_cookie_length
    if baseline_cookie_length is not None and baseline_cookie_length >= LARGE_SESSION_COOKIE:
        client = getattr(network, "client", None)
        if client is not None:
            client.cookies.clear()
    result["patch_evidence"] = patch_result if patch_result is not None else await collect_patch_evidence(network, url, baseline)
    if session_warning_shape(baseline) is None:
        first_shape = None
        for attempt in range(2):
            if attempt and first_shape is None:
                break
            headers, body = session_warning_probe(secrets.token_hex(8))
            observation = {"type": "session_warning_probe", "attempt": attempt + 1,
                           "url": url, "request_bytes": len(body)}
            try:
                response = await network.request("POST", url, follow=False, limit=65536,
                                                 headers=headers, content=body)
                shape = session_warning_shape(response)
                observation.update(http_status=response.status, shape=shape or "not_visible")
                cookie_length = php_session_cookie_length(response.headers)
                if cookie_length is not None:
                    observation["php_session_cookie_length"] = cookie_length
            except Stopped:
                raise
            except Exception as exc:
                result["evidence"].append({**observation, "shape": "request_error",
                                           "error": type(exc).__name__})
                result["reason"] = "The small session-path request failed; patch status remains unknown."
                return result
            result["evidence"].append(observation)
            if unusual_cookie_length(cookie_length, baseline_cookie_length):
                result["status"] = "SESSION_COOKIE_LENGTH_ANOMALY"
                result["reason"] = ("An unusually long PHP session cookie appeared after the small session check. "
                                    "Only its length was retained; this is not direct CVE confirmation.")
                client = getattr(network, "client", None)
                if client is not None:
                    client.cookies.clear()
                try:
                    recovery = await network.request("GET", url, follow=False, limit=1024,
                                                     headers={"Cookie": ""})
                    result["recovery"] = {"http_status": recovery.status,
                                          "reachable": recovery.status < 500}
                except Stopped:
                    raise
                except Exception as exc:
                    result["recovery"] = {"reachable": False, "error": type(exc).__name__}
                return result
            if response.status >= 400:
                result["reason"] = f"The site returned HTTP {response.status} to the small session-path check; no memory-pressure request followed."
                return result
            if attempt == 0:
                first_shape = shape
                continue
            if shape != first_shape:
                result["reason"] = "Session-path responses disagreed across two requests; different workers or a proxy may be involved."
                return result
            if shape == "unpatched":
                result["mode"] = "SESSION_PATCH_ORACLE"
                result["status"] = "UNPATCHED_SESSION_PATH"
                result["reason"] = ("Two small requests showed the pre-fix PHP session-write behavior. "
                                    "This identifies an affected code path, not code execution or memory disclosure.")
                result["cves"] = {c: "AFFECTED_BUILD_BEHAVIOR_OBSERVED" for c in CVES}
                return result
            result["status"] = "PATCHED_SESSION_PATH"
            result["mode"] = "SESSION_PATCH_ORACLE"
            result["reason"] = ("Two small requests showed the post-fix PHP session behavior. "
                                "This does not prove all workers or both CVE fixes are present.")
            result["patch_evidence"]["session_warning"] = "POST_FIX_BEHAVIOR_OBSERVED"
            return result
    if wordpress_login and session_warning_shape(baseline) is None:
        login_url = urljoin(url, "/wp-login.php")
        if login_url != url:
            try:
                login = await network.request("GET", login_url, follow=False, limit=65536,
                                              headers={"Cookie": ""})
                result["evidence"].append({"type": "dynamic_php_path", "url": login_url,
                                           "http_status": login.status})
                if login.status == 200:
                    follow_up = await collect_active_evidence(network, login_url, login,
                                                              result["patch_evidence"], allow_oom=False)
                    follow_up["evidence"] = result["evidence"] + follow_up["evidence"]
                    if follow_up["status"] in ("UNPATCHED_SESSION_PATH", "PATCHED_SESSION_PATH",
                                               "SESSION_COOKIE_LENGTH_ANOMALY"):
                        return follow_up
                    if any(e.get("shape") == "request_error" or e.get("http_status", 0) >= 400
                           for e in follow_up["evidence"] if e.get("type") == "session_warning_probe"):
                        return follow_up
                    result["evidence"] = follow_up["evidence"]
            except Stopped:
                raise
            except Exception as exc:
                result["evidence"].append({"type": "dynamic_php_path", "url": login_url,
                                           "error": type(exc).__name__})
    if not allow_oom:
        return result
    for method in ("part_headers", "nested_empty_files", "session_upload_progress"):
        headers, body = multipart_probe(method, secrets.token_hex(8))
        headers["Cookie"] = ""  # Do not reuse any cookie seen during passive inventory.
        observation = {"type": "bounded_oom_probe", "method": method, "url": url,
                       "request_bytes": len(body), "interpretation": "OOM or HTTP failure is not a CVE signature."}
        try:
            response = await network.request("POST", url, follow=False, limit=4096,
                                             headers=headers, content=body)
            observation["http_status"] = response.status
            cookie_length = php_session_cookie_length(response.headers)
            if cookie_length is not None:
                observation["php_session_cookie_length"] = cookie_length
            if unusual_cookie_length(cookie_length, baseline_cookie_length):
                observation["session_cookie_length_anomaly"] = True
                observation["observation"] = "SESSION_COOKIE_LENGTH_ANOMALY"
                result["status"] = "SESSION_COOKIE_LENGTH_ANOMALY"
                result["reason"] = ("An unusually long PHP session cookie appeared after a probe. "
                                    "Only its length was retained; this is not direct CVE confirmation.")
                # Do not replay an anomalous cookie on the recovery request.
                client = getattr(network, "client", None)
                if client is not None:
                    client.cookies.clear()
            elif OOM_TEXT.search(response.text):
                observation["observation"] = "OOM_TEXT_OBSERVED"
                result["status"] = "OOM_OBSERVED"
                result["reason"] = "A memory exhaustion message appeared. This can happen with both fixed and affected PHP builds; it does not confirm either CVE."
            elif response.status in (403, 405, 413, 415, 429):
                observation["observation"] = "REJECTED_OR_THROTTLED"
                result["status"] = "INCONCLUSIVE"
                result["reason"] = f"The server rejected or limited the active request (HTTP {response.status}); patch status remains unknown."
            elif response.status >= 500:
                observation["observation"] = "SERVER_ERROR_UNSPECIFIC"
                result["status"] = "INCONCLUSIVE"
                result["reason"] = f"The server returned HTTP {response.status}; this is not a defect-specific result."
            else:
                observation["observation"] = "HTTP_RESPONSE_RECEIVED"
                result["status"] = "NO_OOM_OBSERVED"
        except Stopped:
            raise
        except Exception as exc:
            observation.update(observation="REQUEST_ERROR_UNSPECIFIC", error=type(exc).__name__)
            result["status"] = "INCONCLUSIVE"
        result["evidence"].append(observation)
        if observation["observation"] != "HTTP_RESPONSE_RECEIVED":
            break
    if result["status"] == "NO_OOM_OBSERVED":
        result["reason"] = "All bounded active requests received ordinary HTTP responses; no memory error was seen. This does not verify that PHP is patched."
    try:
        response = await network.request("GET", url, follow=False, limit=1024,
                                         headers={"Cookie": ""})
        result["recovery"] = {"http_status": response.status,
                              "reachable": response.status < 500}
        cookie_length = php_session_cookie_length(response.headers)
        if cookie_length is not None:
            result["recovery"]["php_session_cookie_length"] = cookie_length
        if unusual_cookie_length(cookie_length, baseline_cookie_length):
            result["recovery"]["session_cookie_length_anomaly"] = True
            result["status"] = "SESSION_COOKIE_LENGTH_ANOMALY"
            result["reason"] = ("An unusually long PHP session cookie appeared during recovery. "
                                "Only its length was retained; this is not direct CVE confirmation.")
            client = getattr(network, "client", None)
            if client is not None:
                client.cookies.clear()
    except Stopped:
        raise
    except Exception as exc:
        result["recovery"] = {"reachable": False, "error": type(exc).__name__}
    if not result["recovery"]["reachable"]:
        result["reason"] += " Recovery request failed; inspect service health immediately."
    return result
