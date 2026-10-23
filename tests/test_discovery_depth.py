import asyncio
import json
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import dns.exception
import dns.resolver
import httpx

from hunter.checker import patch_evidence
from hunter.crawl import crawl_pages, page_links
from hunter.discovery import DNSResult, discover, passive_names, public_link_names, resolve_details, subdomain_center_names, thc_names
from hunter.engine import Control, run_scan
from hunter.models import CVES, ScanOptions, Target
from hunter.network import Network, Response
from hunter.tls import inspect_tls


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    def options(self, **kwargs):
        return ScanOptions([Target("example.test")], interval=0, **kwargs)

    async def test_subdomain_center_adds_only_in_scope_names_and_reports_cap(self):
        requests, logs = [], []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, headers={"X-Truncated": "true"},
                                  json=["api.example.test", "shared.example.test", "outside.test",
                                        "*.wild.example.test", "example.test"])
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            names = await subdomain_center_names("example.test", network, logs.append)
        finally:
            await network.close()
        self.assertEqual(names, {"api.example.test": {"Subdomain Center"},
                                 "shared.example.test": {"Subdomain Center"}})
        self.assertTrue(any("Subdomain Center: PARTIAL (anonymous result cap)" in line for line in logs))
        self.assertEqual([request.method for request in requests], ["GET"])
        self.assertEqual(requests[0].url.host, "api.subdomain.center")

    async def test_subdomain_center_failure_is_partial_not_empty_success(self):
        logs = []
        network = Network(self.options(), Control(), httpx.MockTransport(lambda _: httpx.Response(429)))
        try:
            self.assertEqual(await subdomain_center_names("example.test", network, logs.append), {})
        finally:
            await network.close()
        self.assertTrue(any("Subdomain Center: PARTIAL (HTTP 429" in line for line in logs))

    async def test_thc_paginates_and_rejects_out_of_scope_names(self):
        requests, logs = [], []
        def handler(request):
            requests.append(request)
            cursor = json.loads(request.content)["page_state"]
            if not cursor:
                return httpx.Response(200, json={"domains": [
                    {"domain": "api.example.test"}, {"domain": "outside.test"}],
                    "next_page_state": "page-2"})
            return httpx.Response(200, json={"domains": [
                {"domain": "api.example.test"}, {"domain": "admin.example.test"},
                {"domain": "*.wild.example.test"}], "next_page_state": ""})
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            names = await thc_names("example.test", network, logs.append)
        finally:
            await network.close()
        self.assertEqual(names, {"api.example.test": {"IP.THC.ORG"},
                                 "admin.example.test": {"IP.THC.ORG"}})
        self.assertEqual([json.loads(r.content)["page_state"] for r in requests], ["", "page-2"])
        self.assertTrue(all(r.method == "POST" and r.url.host == "ip.thc.org" for r in requests))
        self.assertTrue(any("IP.THC.ORG: RETRIEVED" in line for line in logs))

    async def test_thc_http_error_retains_prior_candidates_as_partial(self):
        logs = []
        def handler(request):
            if not json.loads(request.content)["page_state"]:
                return httpx.Response(200, json={"domains": [{"domain": "api.example.test"}],
                                                 "next_page_state": "page-2"})
            return httpx.Response(429)
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            names = await thc_names("example.test", network, logs.append)
        finally:
            await network.close()
        self.assertEqual(names, {"api.example.test": {"IP.THC.ORG"}})
        self.assertTrue(any("IP.THC.ORG: PARTIAL (HTTP 429" in line for line in logs))

    async def test_public_discovery_merges_subdomain_center_without_extra_option(self):
        options = self.options(passive_dns=True)
        network = Network(options, Control(), httpx.MockTransport(lambda _: httpx.Response(200)))
        try:
            with patch("hunter.discovery.passive_names", new=AsyncMock(return_value={})), \
                 patch("hunter.discovery.subdomain_center_names", new=AsyncMock(return_value={
                     "new.example.test": {"Subdomain Center"}})), \
                 patch("hunter.discovery.thc_names", new=AsyncMock(return_value={})), \
                 patch("hunter.discovery.public_link_names", new=AsyncMock(return_value=set())), \
                 patch("hunter.discovery.resolve_details", new=AsyncMock(return_value=DNSResult(
                     {"192.0.2.10"}, {"A": "OK"}))):
                found = await discover(options, network, Control(), lambda _: None)
        finally:
            await network.close()
        added = next(item for item in found if item["target"].host == "new.example.test")
        self.assertEqual(added["source"], {"Subdomain Center"})
        self.assertEqual(added["ips"], {"192.0.2.10"})

    async def test_public_discovery_merges_thc_without_extra_option(self):
        options = self.options(passive_dns=True)
        network = Network(options, Control(), httpx.MockTransport(lambda _: httpx.Response(200)))
        try:
            with patch("hunter.discovery.passive_names", new=AsyncMock(return_value={})), \
                 patch("hunter.discovery.subdomain_center_names", new=AsyncMock(return_value={})), \
                 patch("hunter.discovery.thc_names", new=AsyncMock(return_value={
                     "new.example.test": {"IP.THC.ORG"}})), \
                 patch("hunter.discovery.public_link_names", new=AsyncMock(return_value=set())), \
                 patch("hunter.discovery.resolve_details", new=AsyncMock(return_value=DNSResult(
                     {"192.0.2.10"}, {"A": "OK"}))):
                found = await discover(options, network, Control(), lambda _: None)
        finally:
            await network.close()
        added = next(item for item in found if item["target"].host == "new.example.test")
        self.assertEqual(added["source"], {"IP.THC.ORG"})

    async def test_certspotter_pagination_until_empty(self):
        requests = []
        def handler(request):
            requests.append(str(request.url))
            if request.url.host == "crt.sh":
                return httpx.Response(200, json=[])
            if request.url.host == "api.hackertarget.com":
                return httpx.Response(200, text="")
            after = request.url.params.get("after")
            return httpx.Response(200, json=[] if after == "2" else [{"id": "2" if after else "1", "dns_names": ["b.example.test" if after else "a.example.test"]}])
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            names = await passive_names("example.test", network, lambda _: None)
            self.assertEqual(names, {"a.example.test", "b.example.test"})
            self.assertEqual(len(requests), 5)
        finally:
            await network.close()

    async def test_partial_pagination_is_reported(self):
        logs = []
        handler = httpx.MockTransport(lambda r: httpx.Response(200, json=[{"id": "1", "dns_names": ["a.example.test"]}]))
        network = Network(self.options(), Control(), handler)
        try:
            await passive_names("example.test", network, logs.append, max_pages=1)
            self.assertTrue(any("PARTIAL" in line for line in logs))
        finally:
            await network.close()

    async def test_public_hostsearch_adds_only_in_scope_names(self):
        logs = []
        def handler(request):
            if request.url.host == "crt.sh":
                return httpx.Response(200, json=[])
            if request.url.host == "api.certspotter.com":
                return httpx.Response(429)
            return httpx.Response(200, text="""ml.example.test,192.0.2.1
deep.ml.example.test,192.0.2.2
bad.other.test,192.0.2.3
example.test,192.0.2.4
*.wild.example.test,192.0.2.5
""")
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            names = await passive_names("example.test", network, logs.append, with_sources=True)
        finally:
            await network.close()
        self.assertEqual(names, {"ml.example.test": {"HackerTarget"},
                                 "deep.ml.example.test": {"HackerTarget"}})
        self.assertTrue(any("Cert Spotter: PARTIAL" in line for line in logs))

    async def test_crt_transient_failure_is_retried_once(self):
        attempts = 0
        def handler(request):
            nonlocal attempts
            if request.url.host == "crt.sh":
                attempts += 1
                if attempts == 1:
                    raise httpx.ReadTimeout("temporary")
                return httpx.Response(200, json=[{"name_value": "a.example.test"}])
            return httpx.Response(200, text="") if request.url.host == "api.hackertarget.com" else httpx.Response(200, json=[])
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            names = await passive_names("example.test", network, lambda _: None)
        finally:
            await network.close()
        self.assertEqual(attempts, 2)
        self.assertIn("a.example.test", names)

    async def test_public_site_links_find_subdomains_without_following_foreign_links(self):
        requests = []
        def handler(request):
            requests.append((request.method, str(request.url)))
            return httpx.Response(200, headers={"content-type": "text/html"}, text=(
                '<a href="https://delivery.example.test/menu">Delivery</a>'
                '<a href="//catering.example.test/">Catering</a>'
                '<a href="https://external.test/">Other</a>'
                '<script>"https://fake.example.test/"</script>'))
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            names = await public_link_names("example.test", network, lambda _: None)
        finally:
            await network.close()
        self.assertEqual(names, {"delivery.example.test", "catering.example.test"})
        self.assertEqual(requests, [("GET", "https://example.test/")])

    async def test_public_links_recover_subdomain_when_certificate_source_is_empty(self):
        requests, events = [], []
        def handler(request):
            requests.append(str(request.url))
            if request.url.host == "example.test":
                return httpx.Response(200, headers={"content-type": "text/html"},
                                      text='<a href="https://delivery.example.test/">Delivery</a>')
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text='<meta name="generator" content="WordPress">')
        options = self.options(passive_dns=True)
        resolved = DNSResult({"192.0.2.1"}, {"A": "OK"})
        with patch("hunter.discovery.passive_names", new=AsyncMock(return_value={})), \
             patch("hunter.discovery.subdomain_center_names", new=AsyncMock(return_value={})), \
             patch("hunter.discovery.thc_names", new=AsyncMock(return_value={})), \
             patch("hunter.discovery.resolve_details", new=AsyncMock(return_value=resolved)), \
             patch("hunter.engine.resolve_details", new=AsyncMock(return_value=resolved)):
            await run_scan(options, Control(), events.append, httpx.MockTransport(handler))
        found = [e["asset"] for e in events if e["type"] == "asset" and
                 e["asset"]["url"] == "https://delivery.example.test/" and e["asset"]["php"] == "LIKELY"]
        self.assertTrue(found)
        self.assertTrue(all(url.startswith("https://example.test/") or
                            url.startswith("http://example.test/") or
                            "delivery.example.test" in url for url in requests))

    async def test_public_link_prefetch_does_not_consume_php_cookie_signal(self):
        requests, events = [], []
        def handler(request):
            requests.append(request)
            headers = {"content-type": "text/html"}
            if "ci_session=" not in request.headers.get("cookie", ""):
                headers["set-cookie"] = "ci_session=SECRET; Path=/"
            return httpx.Response(200, headers=headers, text="<h1>Welcome</h1>")
        options = self.options(passive_dns=True)
        resolved = DNSResult({"192.0.2.1"}, {"A": "OK"})
        with patch("hunter.discovery.passive_names", new=AsyncMock(return_value={})), \
             patch("hunter.discovery.subdomain_center_names", new=AsyncMock(return_value={})), \
             patch("hunter.discovery.thc_names", new=AsyncMock(return_value={})), \
             patch("hunter.discovery.resolve_details", new=AsyncMock(return_value=resolved)), \
             patch("hunter.engine.resolve_details", new=AsyncMock(return_value=resolved)):
            await run_scan(options, Control(), events.append, httpx.MockTransport(handler))
        https = [e["asset"] for e in events if e["type"] == "asset" and
                 e["asset"]["url"] == "https://example.test/" and e["asset"]["php"] == "LIKELY"]
        self.assertTrue(https)
        self.assertTrue(all("ci_session=" not in r.headers.get("cookie", "") for r in requests[:2]))

    async def test_dns_timeout_distinct_from_nodata(self):
        resolver = AsyncMock()
        calls = []
        async def resolve(host, kind, **kwargs):
            calls.append(kind)
            if kind == "A":
                raise dns.exception.Timeout()
            raise dns.resolver.NoAnswer()
        resolver.resolve.side_effect = resolve
        with patch("hunter.discovery.dns.asyncresolver.Resolver", return_value=resolver):
            result = await resolve_details("example.test", 0.1)
        self.assertEqual(result.statuses, {"A": "TIMEOUT", "AAAA": "NODATA"})
        self.assertEqual(calls.count("A"), 2)
        self.assertEqual(calls.count("AAAA"), 1)

    async def test_unresolved_input_retained_without_http(self):
        events, requests = [], []
        def handler(request):
            requests.append(request)
            return httpx.Response(200)
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=DNSResult(set(), {"A": "TIMEOUT"}))):
            await run_scan(self.options(), Control(), events.append, httpx.MockTransport(handler))
        self.assertFalse(requests)
        self.assertEqual(events[-1]["coverage"]["dns_unresolved"], 1)
        assets = [event["asset"] for event in events if event["type"] == "asset" and event["asset"]["assessment"] == "DNS_UNRESOLVED"]
        self.assertEqual(len(assets), 2)

    async def test_pinned_request_preserves_host_sni_and_identity(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, text="OK")
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        try:
            response = await network.request_ip("GET", "https://example.test:8443/app", "192.0.2.1")
            self.assertEqual(requests[0].url.host, "192.0.2.1")
            self.assertEqual(requests[0].headers["host"], "example.test:8443")
            self.assertEqual(requests[0].extensions["sni_hostname"], "example.test")
            self.assertEqual(response.url, "https://example.test:8443/app")
        finally:
            await network.close()

    async def test_backend_results_remain_separate(self):
        options = self.options(all_addresses=True)
        events = []
        result = DNSResult({"192.0.2.1", "2001:db8::1"}, {"A": "OK", "AAAA": "OK"})
        with patch("hunter.engine.resolve_details", new=AsyncMock(return_value=result)):
            await run_scan(options, Control(), events.append, httpx.MockTransport(lambda r: httpx.Response(200)))
        checked = [e["asset"] for e in events if e["type"] == "asset" and e["asset"]["assessment"] != "PENDING"]
        self.assertEqual(len({a["id"] for a in checked}), 4)
        self.assertEqual({a["connect_ip"] for a in checked}, result.ips)

    async def test_crawl_is_bounded_and_does_not_submit_forms(self):
        requested = []
        def handler(request):
            requested.append(request)
            return httpx.Response(200, text='<a href="/other.php">Next</a>')
        network = Network(self.options(), Control(), httpx.MockTransport(handler))
        first = Response("https://example.test/", 200, {}, '<a href="/portal.php">App</a><form action="/upload"></form><a href="/logout">Out</a><a href="https://outside.test/">Elsewhere</a>', 1)
        self.assertEqual(page_links(first, first.url), ["https://example.test/portal.php"])
        try:
            pages, report = await crawl_pages(network, first, max_pages=3)
            self.assertEqual(len(pages), 2)
            self.assertTrue(report["partial"])
            self.assertTrue(all(r.method == "GET" for r in requested))
        finally:
            await network.close()


class PatchParserTests(unittest.TestCase):
    def test_requires_full_info_shape_and_valid_directive_row(self):
        text = '<title>phpinfo()</title><h1>PHP Version 8.4.27</h1><h1>Configuration</h1><table><tr><td>memory_hard_limit_percent</td><td>no value</td><td>no value</td></tr></table>'
        evidence = patch_evidence(Response("http://test/", 200, {}, text, 1))
        self.assertTrue(evidence["oom_patch_feature"])
        self.assertIsNone(patch_evidence(Response("http://test/", 200, {}, "memory_hard_limit_percent", 1)))
        self.assertIsNone(patch_evidence(Response("http://test/", 200, {}, text, 1, truncated=True)))


class TLSTests(unittest.TestCase):
    def test_invalid_certificate_still_identified_as_tls_service(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
                .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test"), x509.DNSName("app.example.test")]), critical=False)
                .sign(key, hashes.SHA256()))
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
            def log_message(self, *_):
                pass
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/"cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (path/"key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(path/"cert.pem", path/"key.pem")
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = asyncio.run(inspect_tls(f"https://example.test:{server.server_port}/", address="127.0.0.1"))
                self.assertEqual(result["status"], "TLS_SERVICE_OBSERVED")
                self.assertFalse(result["certificate_verified"])
                self.assertIn("app.example.test", result["sans"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
