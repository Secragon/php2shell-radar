import asyncio
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from hunter.checker import MAX_PROBE_BYTES, collect_active_evidence, collect_patch_evidence, multipart_probe, php_session_cookie_length, session_warning_probe, session_warning_shape
from hunter.detection import fingerprint
from hunter.discovery import DNSResult, discover, passive_names
from hunter.engine import Control, run_scan, wildcard_page_match
from hunter.models import CVES, ScanOptions, Target, endpoints, parse_targets, passive_decisive, triage_assessment, version_assessment
from hunter.network import Network, Response, Stopped
from hunter.storage import Store, export_visible_results


class ModelTests(unittest.TestCase):
    def test_matching_wildcard_error_page_is_not_a_php_site(self):
        page = Response("https://random.example.test/", 404,
                        {"content-type": "text/html", "server": "cloudflare"},
                        '<a href="/login.php">Not found</a>', 1)
        baseline = fingerprint(page, ["example.test"])
        candidate = fingerprint(Response("https://admin.example.test/", 404,
                                         page.headers, page.text, 1), ["example.test"])
        self.assertEqual(candidate["php"], "LIKELY")
        self.assertTrue(wildcard_page_match(candidate, baseline))
        self.assertFalse(wildcard_page_match(
            fingerprint(Response("https://real.example.test/", 404, page.headers,
                                 "<h1>Different site</h1>", 1), ["example.test"]), baseline))

    def test_dynamic_wildcard_error_template_is_still_one_page(self):
        words = " ".join(f"word{number}" for number in range(100))
        template = f"<title>Shared server error</title><p>{words}</p>"
        changed = template.replace("word30", "unique30")
        headers = {"content-type": "text/html", "server": "cloudflare"}
        baseline = fingerprint(Response("https://random.example.test/", 404,
                                        headers, template, 1), ["example.test"])
        candidate = fingerprint(Response("https://candidate.example.test/", 404,
                                         headers, changed, 1), ["example.test"])
        self.assertTrue(wildcard_page_match(candidate, baseline))

    def test_wildcard_403_echoing_each_hostname_is_not_a_separate_site(self):
        headers = {"content-type": "text/html", "server": "Apache"}
        def page(host, message="No site configured at this address."):
            return fingerprint(Response(f"http://{host}/", 403, headers,
                                        f"<title>Resource not found</title><h2>{host}</h2><p>{message}</p>", 1),
                               ["example.test"])
        baseline = page("radar-random.example.test")
        candidate = page("admin.example.test")
        self.assertNotEqual(candidate["content_sha256"], baseline["content_sha256"])
        self.assertEqual(candidate["host_neutral_sha256"], baseline["host_neutral_sha256"])
        self.assertTrue(wildcard_page_match(candidate, baseline))
        self.assertFalse(wildcard_page_match(page("real.example.test", "Restricted site"), baseline))

    def test_legacy_warning_prefix_is_not_treated_as_validated_patch_oracle(self):
        warnings = ("Warning: Unknown: Session ID is too long or contains illegal characters\n"
                    "Warning: Unknown: Failed to read session data\n"
                    "Warning: Unknown: Failed to write session data (files)")
        response = Response("https://a.test/", 500, {}, warnings, len(warnings))
        self.assertIsNone(session_warning_shape(response))

    def test_target_parsing_idna_ipv6_and_explicit_paths(self):
        targets = parse_targets("EXAMPLE.com\nexample.com\nhttps://app.example.com:8443/login?a=1#x\nhttp://[::1]:8000/")
        self.assertEqual(len(targets), 3)
        self.assertEqual(targets[1].url, "https://app.example.com:8443/login?a=1")
        self.assertEqual(targets[2].host, "::1")
        self.assertEqual(parse_targets("пример.бг")[0].host, "xn--e1afmkfd.xn--90ae")

    def test_invalid_input(self):
        for text in ("", "ftp://example.com", "https://a:b@example.com", "a.com:99999", "*.a.com", "example.com/path", "-bad.example"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_targets(text)

    def test_default_does_not_expand_explicit_url(self):
        target = parse_targets("https://example.com:8443/app")[0]
        self.assertEqual(endpoints(target, ScanOptions([target])), [target.url])
        bare = Target("example.com")
        self.assertEqual(len(endpoints(bare, ScanOptions([bare]))), 2)

    def test_ports_include_both_protocols_and_validate_dedup(self):
        target = Target("example.com")
        options = ScanOptions([target], extra_ports=True, ports=[80, 443, 8080])
        urls = endpoints(target, options)
        self.assertEqual(len(urls), 4)
        self.assertIn("https://example.com:8080/", urls)

    def test_version_boundaries_and_backports(self):
        for branch, last, first in (("8.2", 34, 35), ("8.3", 35, 36), ("8.4", 26, 27), ("8.5", 11, 12)):
            self.assertEqual(version_assessment(f"{branch}.{last}")["status"], "POTENTIALLY_AFFECTED")
            self.assertEqual(version_assessment(f"{branch}.{first}")["status"], "FIXED_VERSION_REPORTED")
        self.assertEqual(version_assessment("8.3.6-0ubuntu0.24.04.13")["status"], "BUILD_VERIFICATION_REQUIRED")
        self.assertEqual(version_assessment("8.5.12RC1")["status"], "BUILD_VERIFICATION_REQUIRED")
        for value in (None, "garbage", "8.6.0", "5.3.29"):
            self.assertEqual(version_assessment(value)["status"], "UNKNOWN")

    def test_detection_evidence_and_cookie_redaction(self):
        response = Response("https://a.test/", 200, {"x-powered-by": "PHP/8.4.26", "set-cookie": "PHPSESSID=SECRET; path=/", "cf-ray": "123"}, "", 10)
        asset = fingerprint(response)
        self.assertEqual(asset["php"], "DETECTED")
        self.assertEqual(asset["version"], "8.4.26")
        self.assertEqual(set(asset["cves"]), set(CVES))
        self.assertNotIn("SECRET", json.dumps(asset))
        self.assertEqual(asset["proxy"], ["Cloudflare"])
        unknown = fingerprint(Response("https://a.test/", 200, {}, "hello", 1))
        self.assertEqual(unknown["php"], "NOT_ESTABLISHED")
        self.assertEqual(unknown["assessment"], "UNKNOWN")

    def test_unique_common_dns_names(self):
        words = Path("hunter/data/subdomains.txt").read_text().split()
        self.assertEqual(len(words), 100)
        self.assertEqual(len(set(words)), len(words))

    def test_conflicting_versions_and_application_hints(self):
        response = Response("https://a.test/", 200,
                            {"x-powered-by": "PHP/8.4.26", "server": "Apache PHP/8.4.27"}, "", 1)
        asset = fingerprint(response)
        self.assertIsNone(asset["version"])
        self.assertEqual(asset["assessment"], "UNKNOWN")
        hint = fingerprint(Response("https://a.test/", 200, {}, '<script src="/wp-content/test.js"></script>', 1))
        self.assertEqual(hint["php"], "LIKELY")
        self.assertEqual(hint["assessment"], "UNKNOWN")

    def test_version_triage_retain_evidence_limits(self):
        def asset(version):
            return fingerprint(Response("https://a.test/", 200,
                                        {"X-Powered-By": f"PHP/{version}"}, "", 1))
        self.assertEqual(triage_assessment(asset("8.4.27"))[0], "Fixed version")
        self.assertEqual(triage_assessment(asset("8.4.26"))[0], "At risk")
        self.assertEqual(triage_assessment(asset("8.4.26-ubuntu1"))[0], "Unconfirmed")
        old = asset("8.4.26")
        old["patch_evidence"] = {"status": "PATCH_FEATURE_OBSERVED"}
        self.assertEqual(triage_assessment(old)[0], "Unconfirmed")
        proxied = asset("8.4.26")
        proxied["proxy"] = ["Cloudflare"]
        self.assertEqual(triage_assessment(proxied)[0], "At risk")
        proxied_without_version = fingerprint(Response("https://a.test/", 200,
            {"X-Powered-By": "PHP", "CF-Ray": "example"}, "", 1))
        self.assertEqual(triage_assessment(proxied_without_version)[0], "Unconfirmed")
        partial = asset("8.4.26")
        partial["detection_partial"] = True
        self.assertEqual(triage_assessment(partial)[0], "At risk")
        partial["active"] = {"status": "NO_OOM_OBSERVED"}
        self.assertEqual(triage_assessment(partial)[0], "At risk")
        partial["active"] = {"status": "PATCHED_SESSION_PATH"}
        self.assertEqual(triage_assessment(partial)[0], "Unconfirmed")
        self.assertFalse(passive_decisive(asset("8.4.26")))
        self.assertTrue(passive_decisive(asset("8.4.27")))
        wildcard = asset("8.4.26")
        wildcard["wildcard_ambiguous"] = True
        self.assertEqual(triage_assessment(wildcard)[0], "Unconfirmed")
        self.assertFalse(passive_decisive(wildcard))


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_rotating_wildcard_ip_still_compares_http_error_page(self):
        host = {"target": Target("account.example.test"), "source": {"active DNS"},
                "ips": {"127.0.0.2"}, "dns": {"A": "OK"}, "wildcard": False,
                "wildcard_root": "example.test", "wildcard_probe": "hunter-random.example.test"}
        events = []
        page = '<a href="/login.php">Not found</a>'
        transport = httpx.MockTransport(lambda request: httpx.Response(
            404, headers={"content-type": "text/html", "server": "cloudflare"}, text=page))
        with patch("hunter.engine.discover", new=AsyncMock(return_value=[host])):
            await run_scan(ScanOptions([Target("example.test")], passive_dns=False,
                                       active_dns=False, tls_names=False, interval=0),
                           Control(), events.append, transport)
        checked = [event["asset"] for event in events if event["type"] == "asset" and
                   event["asset"].get("http_status") == 404]
        self.assertEqual(len(checked), 2)
        self.assertTrue(all(asset.get("wildcard_http_match") for asset in checked))
        self.assertTrue(all(asset["php"] == "NOT_ESTABLISHED" for asset in checked))

    def options(self, **kwargs):
        return ScanOptions([Target("example.test")], interval=0, **kwargs)

    async def test_bounded_body_and_redirect_record(self):
        def handler(request):
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "/final"})
            return httpx.Response(200, content=b"x" * 200000)
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            response = await network.request("GET", "https://example.test/", limit=100)
            self.assertEqual(len(response.text), 100)
            self.assertEqual(response.redirects, ["https://example.test/final"])
        finally:
            await network.close()

    async def test_patch_collection_never_claims_cve_confirmation(self):
        requests = []
        def handler(request):
            requests.append(request)
            body = "Session ID is too long or contains illegal characters" if len(requests) == 2 else "ok"
            return httpx.Response(200, text=body)
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        baseline = Response("https://example.test/", 200, {}, "baseline", 1)
        try:
            result = await collect_patch_evidence(network, baseline.url, baseline)
            self.assertEqual(result["status"], "INCONCLUSIVE")
            self.assertEqual(set(result["cves"].values()), {"NOT_CONFIRMED"})
            self.assertEqual(len(requests), 2)
            self.assertTrue(all(len(request.content) < 1024 for request in requests))
            self.assertTrue(all(request.method == "GET" for request in requests))
        finally:
            await network.close()

    async def test_patch_collection_negative_and_blocked_are_not_safe_verdicts(self):
        for code, expected in ((200, "INCONCLUSIVE"), (403, "INCONCLUSIVE"), (404, "INCONCLUSIVE"), (500, "INCONCLUSIVE"), (429, "INCONCLUSIVE"), (302, "INCONCLUSIVE")):
            network = Network(self.options(), Control(), httpx.MockTransport(lambda r: httpx.Response(code, text="ok")))
            try:
                result = await collect_patch_evidence(network, "https://example.test/", Response("", 200, {}, "", 1))
                self.assertEqual(result["status"], expected)
            finally:
                await network.close()

    async def test_active_probe_is_bounded_and_never_confirms_cve_from_5xx(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(502 if request.method == "POST" and len(request.content) > 1024 else 200)
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        baseline = Response("https://example.test/index.php", 200,
                            {"X-Powered-By": "PHP/8.4.26"}, "", 1)
        try:
            result = await collect_active_evidence(network, baseline.url, baseline)
            posts = [r for r in requests if r.method == "POST"]
            self.assertEqual(len(posts), 2)
            self.assertTrue(all(len(post.content) <= MAX_PROBE_BYTES for post in posts))
            self.assertTrue(all(b"<?php" not in post.content for post in posts))
            self.assertEqual(result["evidence"][1]["observation"], "SERVER_ERROR_UNSPECIFIC")
            self.assertTrue(result["recovery"]["reachable"])
            self.assertEqual(set(result["cves"].values()), {"NOT_CONFIRMED"})
        finally:
            await network.close()

    async def test_three_distinct_oom_paths_never_turn_normal_response_into_fixed(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, text="ok")
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        baseline = Response("https://example.test/index.php", 200, {}, "", 1)
        try:
            result = await collect_active_evidence(network, baseline.url, baseline,
                                                   {"status": "INCONCLUSIVE", "reported_versions": []})
            posts = [r for r in requests if r.method == "POST"]
            self.assertEqual(len(posts), 4)
            self.assertEqual(len(requests), 5)
            self.assertTrue(all(len(r.content) <= MAX_PROBE_BYTES for r in posts))
            self.assertEqual([e["method"] for e in result["evidence"] if e["type"] == "bounded_oom_probe"],
                             ["part_headers", "nested_empty_files", "session_upload_progress"])
            self.assertEqual(result["status"], "NO_OOM_OBSERVED")
            self.assertEqual(set(result["cves"].values()), {"NOT_CONFIRMED"})
        finally:
            await network.close()

    async def test_upload_progress_probe_uses_fresh_sid_without_executable_payload(self):
        headers, body = multipart_probe("session_upload_progress", "0123456789abcdef")
        self.assertLessEqual(len(body), MAX_PROBE_BYTES)
        self.assertIn(b'name="PHPSESSID"\r\n\r\n0123456789abcdef', body)
        self.assertIn(b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nradar', body)
        self.assertEqual(body.count(b'filename="f'), 4000)
        self.assertNotIn(b"<?php", body)
        self.assertNotIn(b"system(", body)
        self.assertIn("multipart/form-data", headers["Content-Type"])

    async def test_small_session_oracle_repeats_before_vulnerable_verdict(self):
        warnings = ("Warning: PHP Request Startup: Session ID is too long or contains illegal characters\n"
                    "Warning: PHP Request Startup: Failed to read session data\n"
                    "Warning: PHP Request Startup: Failed to write session data (files)")
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, text=warnings)
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        baseline = Response("https://example.test/index.php", 200, {}, "baseline", 1)
        try:
            result = await collect_active_evidence(network, baseline.url, baseline,
                                                   {"status": "INCONCLUSIVE", "reported_versions": []})
        finally:
            await network.close()
        self.assertEqual(result["status"], "UNPATCHED_SESSION_PATH")
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(r.method == "POST" and len(r.content) < 1024 for r in requests))
        self.assertTrue(all(b"<?php" not in r.content for r in requests))
        self.assertNotEqual(requests[0].content, requests[1].content)
        self.assertEqual([e["shape"] for e in result["evidence"]], ["unpatched", "unpatched"])
        self.assertEqual(triage_assessment({"php": "DETECTED", "assessment": "UNKNOWN", "active": result})[0], "Vulnerable")
        self.assertEqual(triage_assessment({"php": "DETECTED", "assessment": "FIXED_VERSION_REPORTED", "active": result})[0], "Unconfirmed")

    async def test_post_fix_session_oracle_downgrades_old_version_conflict(self):
        warnings = ("Warning: PHP Request Startup: Session ID is too long or contains illegal characters\n"
                    "Warning: PHP Request Startup: Failed to read session data")
        network = Network(self.options(), Control(), httpx.MockTransport(lambda _: httpx.Response(200, text=warnings)))
        baseline = Response("https://example.test/index.php", 200, {}, "baseline", 1)
        try:
            result = await collect_active_evidence(network, baseline.url, baseline,
                                                   {"status": "INCONCLUSIVE", "reported_versions": []})
        finally:
            await network.close()
        self.assertEqual(result["status"], "PATCHED_SESSION_PATH")
        asset = fingerprint(Response(baseline.url, 200, {"X-Powered-By": "PHP/8.4.26"}, "", 1))
        asset["active"] = result
        self.assertEqual(triage_assessment(asset)[0], "Unconfirmed")

    async def test_small_oracle_payload_is_bounded_and_contains_no_php_code(self):
        headers, body = session_warning_probe("0123456789abcdef")
        self.assertLess(len(body), 1024)
        self.assertIn(b"radar/0123456789abcdef", body)
        self.assertIn(b"PHP_SESSION_UPLOAD_PROGRESS", body)
        self.assertNotIn(b"<?php", body)
        self.assertIn("multipart/form-data", headers["Content-Type"])

    async def test_literal_oom_stops_second_probe_but_does_not_confirm_cve(self):
        requests = []
        def handler(request):
            requests.append(request.method)
            if request.method == "POST" and len(request.content) > 1024:
                return httpx.Response(500, text="Fatal error: Allowed memory size of 4194304 bytes exhausted")
            return httpx.Response(200)
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        baseline = Response("https://example.test/index.php", 200, {}, "", 1)
        try:
            result = await collect_active_evidence(network, baseline.url, baseline,
                                                   {"status": "INCONCLUSIVE", "reported_versions": []})
            self.assertEqual(requests, ["POST", "POST", "GET"])
            self.assertEqual(result["status"], "OOM_OBSERVED")
            self.assertEqual(set(result["cves"].values()), {"NOT_CONFIRMED"})
        finally:
            await network.close()

    async def test_large_session_cookie_retains_length_only_and_is_not_replayed(self):
        secret = "SENSITIVE_MEMORY_" * 100
        requests = []
        def handler(request):
            requests.append((request.method, request.headers.get("cookie", "")))
            if request.method == "POST":
                return httpx.Response(200, headers={"Set-Cookie": f"PHPSESSID={secret}; Path=/"})
            return httpx.Response(200, text="ok")
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        baseline = Response("https://example.test/index.php", 200,
                            {"Set-Cookie": "PHPSESSID=short; Path=/"}, "", 1)
        network.client.cookies.set("PHPSESSID", "existing_user_session", domain="example.test")
        try:
            result = await collect_active_evidence(network, baseline.url, baseline,
                                                   {"status": "INCONCLUSIVE", "reported_versions": []})
        finally:
            await network.close()
        self.assertEqual(php_session_cookie_length(baseline.headers), 5)
        self.assertEqual(result["status"], "SESSION_COOKIE_LENGTH_ANOMALY")
        self.assertEqual(result["evidence"][0]["php_session_cookie_length"], len(secret))
        self.assertEqual([method for method, _ in requests], ["POST", "GET"])
        self.assertNotIn("existing_user_session", requests[0][1])
        self.assertEqual(requests[1][1], "")
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(set(result["cves"].values()), {"NOT_CONFIRMED"})

    async def test_recovery_cookie_anomaly_is_length_only(self):
        secret = "PRIVATE_" * 200
        def handler(request):
            if request.method == "POST" and len(request.content) > 1024:
                return httpx.Response(500, text="OOM")
            return httpx.Response(200, headers={"Set-Cookie": f"PHPSESSID={secret}; Path=/"} if request.method == "GET" else {})
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        baseline = Response("https://example.test/index.php", 200, {}, "", 1)
        try:
            result = await collect_active_evidence(network, baseline.url, baseline,
                                                   {"status": "INCONCLUSIVE", "reported_versions": []})
        finally:
            await network.close()
        self.assertEqual(result["status"], "SESSION_COOKIE_LENGTH_ANOMALY")
        self.assertEqual(result["recovery"]["php_session_cookie_length"], len(secret))
        self.assertTrue(result["recovery"]["session_cookie_length_anomaly"])
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(set(result["cves"].values()), {"NOT_CONFIRMED"})

    async def test_engine_integration_emits_per_cve_results(self):
        events = []
        handler = httpx.MockTransport(lambda r: httpx.Response(200, headers={"X-Powered-By": "PHP/8.3.35"}, text="OK"))
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(self.options(collect_patch_evidence=True), Control(), events.append, handler)
        finished = events[-1]
        self.assertEqual(finished["status"], "COMPLETED")
        checked = [e["asset"] for e in events if e["type"] == "asset" and e["asset"]["assessment"] != "PENDING"]
        self.assertEqual(len(checked), 2)
        self.assertTrue(all(a["assessment"] == "POTENTIALLY_AFFECTED" for a in checked))
        self.assertTrue(all(a["active"]["status"] == "NOT_RUN" for a in checked))
        self.assertTrue(all(a["patch_evidence"]["status"] == "INCONCLUSIVE" for a in checked))

    async def test_active_engine_reports_context_without_cve_confirmation(self):
        requests, events = [], []
        def handler(request):
            requests.append((request.method, request.url.path))
            return httpx.Response(200, headers={"X-Powered-By": "PHP"}, text="OK")
        target = Target("example.test", "https://example.test/index.php")
        options = ScanOptions([target], active_check=True, interval=0)
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(options, Control(), events.append, httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["verdict"], "Unconfirmed")
        self.assertEqual(asset["active"]["status"], "NO_OOM_OBSERVED")
        self.assertEqual(set(asset["active"]["cves"].values()), {"NOT_CONFIRMED"})
        self.assertEqual(sum(method == "POST" for method, _ in requests), 4)

    async def test_active_engine_emits_vulnerable_for_repeated_pre_fix_session_path(self):
        requests, events = [], []
        warnings = ("Warning: PHP Request Startup: Session ID is too long or contains illegal characters\n"
                    "Warning: PHP Request Startup: Failed to read session data\n"
                    "Warning: PHP Request Startup: Failed to write session data (files)")
        def handler(request):
            requests.append(request)
            if request.method == "POST":
                return httpx.Response(200, text=warnings)
            return httpx.Response(200, headers={"X-Powered-By": "PHP/8.4.26"}, text="OK")
        target = Target("example.test", "https://example.test/index.php")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(),
                           events.append, httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["verdict"], "Vulnerable")
        self.assertEqual(asset["active"]["status"], "UNPATCHED_SESSION_PATH")
        self.assertEqual(len([r for r in requests if r.method == "POST"]), 2)
        self.assertTrue(all(len(r.content) < 1024 for r in requests if r.method == "POST"))

    async def test_small_oracle_discovers_hidden_php_on_error_response_without_oom(self):
        requests, events = [], []
        warnings = ("Warning: PHP Request Startup: Session ID is too long or contains illegal characters\n"
                    "Warning: PHP Request Startup: Failed to read session data\n"
                    "Warning: PHP Request Startup: Failed to write session data (files)")
        def handler(request):
            requests.append(request)
            if request.method == "POST":
                return httpx.Response(500, text=warnings)
            return httpx.Response(200, text="ordinary page")
        target = Target("example.test", "https://example.test/")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(),
                           events.append, httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["php"], "DETECTED")
        self.assertEqual(asset["verdict"], "Vulnerable")
        self.assertEqual(asset["active"]["status"], "UNPATCHED_SESSION_PATH")
        posts = [r for r in requests if r.method == "POST"]
        self.assertEqual(len(posts), 2)
        self.assertTrue(all(len(r.content) < 1024 for r in posts))
        self.assertFalse(any(e["type"] == "bounded_oom_probe" for e in asset["active"]["evidence"]))

    async def test_small_oracle_identifies_php_but_does_not_claim_fixed_on_two_warnings(self):
        warnings = ("Warning: PHP Request Startup: Session ID is too long or contains illegal characters\n"
                    "Warning: PHP Request Startup: Failed to read session data")
        requests, events = [], []
        def handler(request):
            requests.append(request)
            return httpx.Response(500 if request.method == "POST" else 200,
                                  text=warnings if request.method == "POST" else "ordinary page")
        target = Target("example.test", "https://example.test/")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(),
                           events.append, httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["php"], "DETECTED")
        self.assertEqual(asset["verdict"], "Unconfirmed")
        self.assertEqual(asset["active"]["status"], "PATCHED_SESSION_PATH")
        self.assertEqual(sum(r.method == "POST" for r in requests), 2)

    async def test_wordpress_login_path_recovers_hidden_root_oracle(self):
        requests, events = [], []
        warnings = ("Warning: PHP Request Startup: Session ID is too long or contains illegal characters\n"
                    "Warning: PHP Request Startup: Failed to read session data\n"
                    "Warning: PHP Request Startup: Failed to write session data (files)")
        wordpress = '<meta name="generator" content="WordPress 6.7" />'
        def handler(request):
            requests.append((request.method, request.url.path, len(request.content)))
            if request.method == "POST" and request.url.path == "/wp-login.php":
                return httpx.Response(200, text=warnings)
            return httpx.Response(200, text=wordpress if request.method == "GET" else "OK")
        target = Target("example.test", "https://example.test/")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(),
                           events.append, httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["verdict"], "Vulnerable")
        self.assertEqual(asset["active"]["status"], "UNPATCHED_SESSION_PATH")
        self.assertEqual([(method, path) for method, path, _ in requests if method == "POST"],
                         [("POST", "/"), ("POST", "/wp-login.php"), ("POST", "/wp-login.php")])
        self.assertTrue(all(size < 1024 for method, _, size in requests if method == "POST"))
        self.assertTrue(any(e.get("type") == "dynamic_php_path" for e in asset["active"]["evidence"]))

    async def test_wordpress_login_post_fix_pattern_does_not_claim_fixed_version(self):
        warnings = ("Warning: PHP Request Startup: Session ID is too long or contains illegal characters\n"
                    "Warning: PHP Request Startup: Failed to read session data")
        events = []
        def handler(request):
            if request.method == "POST" and request.url.path == "/wp-login.php":
                return httpx.Response(200, text=warnings)
            return httpx.Response(200, text='<meta name="generator" content="WordPress 6.7" />')
        target = Target("example.test", "https://example.test/")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(),
                           events.append, httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["active"]["status"], "PATCHED_SESSION_PATH")
        self.assertEqual(asset["verdict"], "Unconfirmed")

    async def test_active_checks_http_and_https_separately_when_both_serve_php(self):
        events, requests = [], []
        def handler(request):
            requests.append((request.method, request.url.scheme))
            return httpx.Response(200, headers={"X-Powered-By": "PHP/7.4.33"}, text="OK")
        target = Target("example.test")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(), events.append,
                           httpx.MockTransport(handler))
        assets = {e["asset"]["url"]: e["asset"] for e in events if e["type"] == "asset"}
        self.assertEqual({asset["active"]["status"] for asset in assets.values()}, {"NO_OOM_OBSERVED"})
        self.assertEqual(sum(method == "POST" for method, _ in requests), 8)

    async def test_http_upgrade_reuses_https_check(self):
        events, requests = [], []
        def handler(request):
            requests.append((request.method, request.url.scheme))
            if request.url.scheme == "http":
                return httpx.Response(301, headers={"Location": "https://example.test/"})
            return httpx.Response(200, headers={"X-Powered-By": "PHP/7.4.33"}, text="OK")
        target = Target("example.test")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(), events.append,
                           httpx.MockTransport(handler))
        assets = {e["asset"]["url"]: e["asset"] for e in events if e["type"] == "asset"}
        checked = [asset for asset in assets.values() if asset["active"]["status"] == "NO_OOM_OBSERVED"]
        reused = [asset for asset in assets.values() if asset["active"].get("reason_code") == "ALREADY_CHECKED"]
        self.assertEqual(len(checked), 1)
        self.assertEqual(len(reused), 1)
        self.assertEqual(reused[0]["active"]["checked_at"], "https://example.test/")
        self.assertEqual(sum(method == "POST" for method, _ in requests), 4)
        self.assertEqual(sum(method == "POST" and scheme == "http" for method, scheme in requests), 0)

    async def test_active_page_error_is_explicit(self):
        events = []
        def handler(request):
            return httpx.Response(500, headers={"X-Powered-By": "PHP/7.4.33"})
        target = Target("example.test", "https://example.test/")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(), events.append,
                           httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["active"]["reason_code"], "BASELINE_HTTP_ERROR")
        self.assertIn("HTTP 500", asset["active"]["reason"])

    async def test_active_reaches_php_likely_site_without_phpinfo(self):
        requests, events = [], []
        def handler(request):
            requests.append((request.method, request.url.path))
            if request.url.path in ("/phpinfo.php", "/info.php"):
                return httpx.Response(404)
            return httpx.Response(200, text='<meta name="generator" content="WordPress 6.8">')
        target = Target("example.test", "https://example.test/")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(),
                           events.append, httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["php"], "LIKELY")
        self.assertEqual(asset["verdict"], "Unconfirmed")
        self.assertEqual(asset["active"]["status"], "NO_OOM_OBSERVED")
        self.assertEqual(sum(method == "POST" for method, _ in requests), 5)
        self.assertIn(("POST", "/wp-login.php"), requests)

    async def test_fixed_version_skips_active_and_older_version_gets_verification(self):
        for version, verdict in (("8.4.26", "At risk"), ("8.4.27", "Fixed version")):
            with self.subTest(version=version):
                requests, events = [], []
                def handler(request):
                    requests.append((request.method, request.url.path))
                    return httpx.Response(200, headers={"X-Powered-By": f"PHP/{version}"})
                target = Target("example.test", "https://example.test/")
                with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
                    await run_scan(ScanOptions([target], active_check=True, interval=0), Control(), events.append, httpx.MockTransport(handler))
                asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
                self.assertEqual(asset["verdict"], verdict)
                if version == "8.4.27":
                    self.assertEqual(asset["active"]["status"], "SKIPPED_PASSIVE")
                    self.assertEqual(requests, [("GET", "/")])
                else:
                    self.assertEqual(asset["active"]["status"], "NO_OOM_OBSERVED")
                    self.assertEqual(sum(method == "POST" for method, _ in requests), 4)

    async def test_diagnostic_version_resolves_uncertainty_without_post(self):
        requests, events = [], []
        info = ('<html><head><title>phpinfo()</title></head><body><h1>PHP Version 8.4.27</h1>'
                '<h2>Configuration</h2><table><tr><td>memory_hard_limit_percent</td>'
                '<td>no value</td><td>no value</td></tr></table></body></html>')
        def handler(request):
            requests.append((request.method, request.url.path))
            if request.url.path == "/info.php":
                return httpx.Response(200, text=info)
            if request.url.path == "/phpinfo.php":
                return httpx.Response(404)
            return httpx.Response(200, text='<meta name="generator" content="WordPress 6.8">')
        target = Target("example.test", "https://example.test/")
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult({"127.0.0.1"}, {"A": "OK"}))):
            await run_scan(ScanOptions([target], active_check=True, interval=0), Control(), events.append, httpx.MockTransport(handler))
        asset = [e["asset"] for e in events if e["type"] == "asset"][-1]
        self.assertEqual(asset["version"], "8.4.27")
        self.assertEqual(asset["verdict"], "Fixed version")
        self.assertEqual(asset["active"]["status"], "SKIPPED_AFTER_DIAGNOSTIC")
        self.assertEqual(requests, [("GET", "/"), ("GET", "/phpinfo.php"), ("GET", "/info.php")])

    async def test_stop_and_pause(self):
        control = Control()
        control.paused.set()
        pending = asyncio.create_task(control.checkpoint())
        await asyncio.sleep(0.01)
        self.assertFalse(pending.done())
        control.stopped.set()
        with self.assertRaises(Stopped):
            await pending
        events = []
        await run_scan(self.options(), control, events.append)
        self.assertEqual(events[-1]["status"], "STOPPED")
        self.assertFalse(any(e["type"] == "asset" for e in events))

    async def test_wildcard_candidates_retained(self):
        options = self.options(active_dns=True, words=["www", "admin"])
        events = []
        with patch("hunter.discovery.resolve", new=AsyncMock(return_value={"192.0.2.1"})), patch("hunter.discovery.resolve_details", new=AsyncMock(return_value=DNSResult({"192.0.2.1"}, {"A": "OK"}))):
            hosts = await discover(options, None, Control(), events.append)
        self.assertEqual(len(hosts), 3)
        self.assertTrue(all(h.get("wildcard") for h in hosts if h["target"].host != "example.test"))
        self.assertTrue(all(h["scope_roots"] == {"example.test"} for h in hosts))
        self.assertTrue(any("wildcard" in e.get("message", "") for e in events))

    async def test_unreachable_wildcard_tcp_port_skips_repeated_http_attempts(self):
        options = self.options(active_dns=True, words=["www"])
        host = {"target": Target("www.example.test"), "source": {"active DNS"},
                "ips": {"192.0.2.1"}, "dns": DNSResult({"192.0.2.1"}, {"A": "OK"}).document(),
                "wildcard": True, "wildcard_probe": "random.example.test",
                "wildcard_root": "example.test"}
        requests = []
        def handler(request):
            requests.append(str(request.url))
            return httpx.Response(200, text="")
        events = []
        with patch("hunter.engine.discover", new=AsyncMock(return_value=[host])), \
             patch("hunter.engine.tcp_port_reachable", new=AsyncMock(return_value=False)):
            await run_scan(options, Control(), events.append, httpx.MockTransport(handler))
        skipped = [event["asset"] for event in events if event["type"] == "asset" and
                   event["asset"].get("assessment") == "WILDCARD_PORT_UNREACHABLE"]
        self.assertEqual(len(skipped), 2)
        self.assertEqual(events[-1]["coverage"]["wildcard_tcp_skipped"], 2)
        self.assertTrue(all("random.example.test" in url for url in requests))

    async def test_two_passive_sources_dedup_and_domain_matching(self):
        def handler(request):
            if request.url.host == "crt.sh":
                return httpx.Response(200, json=[{"name_value": "api.example.test\n*.example.test\nevil.test"}])
            return httpx.Response(200, json=[{"dns_names": ["api.example.test", "app.example.test"]}])
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            names = await passive_names("example.test", network, lambda _: None)
            self.assertEqual(names, {"api.example.test", "app.example.test"})
        finally:
            await network.close()


class StorageTests(unittest.TestCase):
    def test_roundtrip_and_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "sessions.sqlite3")
            run = {"id": "123", "status": "COMPLETED"}
            asset = {"url": "https://example.test/", "host": "example.test", "error": "=DANGEROUS()", "evidence": [{"type": "header"}]}
            result = {"Address": asset["url"], "HTTP": "200", "PHP": "Detected", "Version": "8.4.26",
                      "Active check": "Off", "Result": "=DANGEROUS()"}
            try:
                store.save_run(run)
                store.save_asset("123", asset)
                self.assertEqual(store.assets("123"), [asset])
                self.assertEqual(store.runs(), [run])
                path = Path(directory) / "out.json"
                export_visible_results(path, [result])
                self.assertEqual(json.loads(path.read_text())["results"], [result])
                path = Path(directory) / "out.csv"
                export_visible_results(path, [result])
                with path.open(encoding="utf-8-sig", newline="") as handle:
                    row = next(csv.DictReader(handle))
                self.assertEqual(row["Result"], "'=DANGEROUS()")
                self.assertEqual(set(row), set(result))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
