import asyncio
import threading
import uuid
from urllib.parse import urlsplit

from hunter.checker import collect_active_evidence, collect_patch_evidence
from hunter.crawl import crawl_pages
from hunter.detection import authority, fingerprint
from hunter.discovery import discover, resolve_details
from hunter.models import CVES, endpoints, passive_decisive, triage_assessment, utc_now, version_assessment
from hunter.network import Network, Stopped, gather_workers
from hunter.site_identity import equivalent_pages
from hunter.tls import inspect_tls


class Control:
    def __init__(self):
        self.paused = threading.Event()
        self.stopped = threading.Event()

    async def checkpoint(self):
        while self.paused.is_set():
            if self.stopped.is_set():
                raise Stopped()
            await asyncio.sleep(0.1)
        if self.stopped.is_set():
            raise Stopped()


def pending_asset(url, target, ips=(), source=("input",), connect_ip=None):
    return {"id": url + (f" [IP {connect_ip}]" if connect_ip else ""), "url": url, "host": target.host,
            "connect_ip": connect_ip, "ips": sorted(ips), "source": sorted(source),
            "php": "PENDING", "assessment": "PENDING", "verdict": "Unconfirmed", "active": {"status": "NOT_RUN"},
            "evidence": [], "version": None, "error": "", "cves": {}}


def merge_diagnostic_version(item, patch):
    """Add a structured phpinfo version without hiding conflicting HTTP evidence."""
    found = patch.get("reported_versions", [])
    if not found:
        return
    versions = sorted(set(item.get("reported_versions", [])) | set(found))
    item["reported_versions"] = versions
    if len(versions) != 1:
        item["version"] = None
        assessment = {"status": "UNKNOWN", "reason": "Conflicting PHP versions across HTTP and diagnostic responses."}
    else:
        item["version"] = versions[0]
        assessment = version_assessment(versions[0])
        item["php"] = "DETECTED"
        item["confidence"] = "high"
    item["assessment"] = assessment["status"]
    item["cves"] = {cve: dict(assessment) for cve in CVES}
    for entry in patch.get("evidence", []):
        if entry.get("reported_version"):
            item["evidence"].append({"type": "active_phpinfo", "source": "diagnostic page",
                                      "value": f"Reported PHP {entry['reported_version']}",
                                      "strength": "strong", "url": entry["url"]})


def wildcard_page_match(item, baseline):
    """A random wildcard hostname serving the same page is not a site."""
    if (not baseline or not isinstance(item.get("http_status"), int) or
            item["http_status"] != baseline.get("http_status")):
        return False
    if any(item.get(field) != baseline.get(field)
           for field in ("php", "version", "server", "technologies")):
        return False
    digest = item.get("content_sha256")
    if digest and digest == baseline.get("content_sha256"):
        return True
    neutral_digest = item.get("host_neutral_sha256")
    if neutral_digest and neutral_digest == baseline.get("host_neutral_sha256"):
        return True
    if item["http_status"] == 200:
        return equivalent_pages(item, baseline)
    first, second = item.get("site_identity") or {}, baseline.get("site_identity") or {}
    a, b = set(first.get("sketch") or ()), set(second.get("sketch") or ())
    return bool(first.get("title") and len(first["title"]) >= 8 and
                first["title"] == second.get("title") and
                min(first.get("captured_chars", 0), second.get("captured_chars", 0)) >= 512 and
                min(len(a), len(b)) >= 20 and len(a & b) / len(a | b) >= 0.85)


async def tcp_port_reachable(address, port, timeout):
    """Check a wildcard IP once before repeating doomed HTTP connections."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, TimeoutError):
        return False


async def run_scan(options, control, emit, transport=None):
    network = Network(options, control, transport)
    emit({"type": "started", "id": str(uuid.uuid4()), "started_at": utc_now(), "options": options.to_dict()})
    completed = 0
    active_probed = {}
    active_lock = asyncio.Lock()  # Never stress two services concurrently.
    coverage = {"dns_unresolved": 0, "http_errors": 0, "tls_errors": 0, "wildcard_candidates": 0,
                "wildcard_http_matches": 0, "wildcard_tcp_skipped": 0,
                "crawl_partial": 0, "sources": []}

    def discovery_event(event):
        if event["type"] == "log":
            coverage["sources"].append(event["message"])
        emit(event)

    try:
        await control.checkpoint()
        if not options.all_addresses:
            for target in options.targets:
                for url in endpoints(target, options):
                    emit({"type": "asset", "asset": pending_asset(url, target)})
        emit({"type": "stage", "stage": "DNS / certificate discovery", "total": 0, "completed": 0})
        hosts = await discover(options, network, control, discovery_event)
        wildcard_baselines = {}
        for root, probe in sorted({(host["wildcard_root"], host["wildcard_probe"])
                                   for host in hosts if host.get("wildcard_probe")}):
            for scheme in ("https", "http"):
                await control.checkpoint()
                try:
                    response = await network.request("GET", f"{scheme}://{probe}/")
                    wildcard_baselines[(root, scheme)] = fingerprint(response, (root,))
                except Exception as exc:
                    emit({"type": "log", "message":
                          f"Wildcard HTTP baseline for {root} ({scheme}): {type(exc).__name__}."})
        wildcard_ports = set()
        for host in hosts:
            if host.get("wildcard"):
                for url in endpoints(host["target"], options):
                    parsed = urlsplit(url)
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    wildcard_ports.update((address, port) for address in host["ips"])
        wildcard_tcp = {}
        for address, port in sorted(wildcard_ports):
            await control.checkpoint()
            wildcard_tcp[(address, port)] = await tcp_port_reachable(address, port, options.timeout)
            if not wildcard_tcp[(address, port)]:
                emit({"type": "log", "message":
                      f"Wildcard DNS address {address}:{port}: TCP unavailable; matching candidates are not HTTP sites."})
        queue, unique = asyncio.Queue(), set()
        for host in hosts:
            await control.checkpoint()
            target = host["target"]
            if "dns" not in host:
                details = await resolve_details(target.host, options.timeout)
                host["dns"], host["ips"] = details.document(), details.ips
            if not host["ips"]:
                coverage["dns_unresolved"] += 1
            if host.get("wildcard"):
                coverage["wildcard_candidates"] += 1
            addresses = sorted(host["ips"]) if options.all_addresses and host["ips"] else [None]
            for url in endpoints(target, options):
                for address in addresses:
                    item = pending_asset(url, target, host["ips"], host["source"], address)
                    item["dns"], item["wildcard_ambiguous"] = host["dns"], host.get("wildcard", False)
                    item["scope_roots"] = sorted(host.get("scope_roots", ()))
                    if host.get("wildcard_root"):
                        item["wildcard_root"] = host["wildcard_root"]
                    if item["id"] in unique:
                        continue
                    unique.add(item["id"])
                    if not host["ips"]:
                        item.update(php="NOT_ESTABLISHED", assessment="DNS_UNRESOLVED",
                                    error="DNS unresolved; inspect DNS status. Candidate retained, HTTP not attempted.")
                    else:
                        parsed = urlsplit(url)
                        port = parsed.port or (443 if parsed.scheme == "https" else 80)
                        if (host.get("wildcard") and
                                all(wildcard_tcp.get((address, port)) is False for address in host["ips"])):
                            item.update(php="NOT_ESTABLISHED", assessment="WILDCARD_PORT_UNREACHABLE",
                                        error=f"Wildcard DNS address has no reachable TCP service on port {port}.")
                            coverage["wildcard_tcp_skipped"] += 1
                        else:
                            queue.put_nowait(item)
                    emit({"type": "asset", "asset": item.copy()})
        total = queue.qsize()
        emit({"type": "stage", "stage": "HTTP / PHP detection", "total": total, "completed": 0})

        async def inspect_response(item, response, check=True):
            item.update(fingerprint(response, (target.host for target in options.targets)))
            if (item.get("wildcard_root") and
                    wildcard_page_match(item, wildcard_baselines.get(
                        (item.get("wildcard_root"), urlsplit(item["url"]).scheme)))):
                item["wildcard_http_match"] = True
                item["php"] = "NOT_ESTABLISHED"
                item["assessment"] = "WILDCARD_RESPONSE"
                item["verdict"] = "Unconfirmed"
                item["verdict_reason"] = "This hostname serves the same page as a random wildcard DNS name."
                coverage["wildcard_http_matches"] += 1
                return item
            if (options.active_check or options.collect_patch_evidence) and check:
                if item["connect_ip"]:
                    # Read patch evidence from this exact backend, never from a random DNS result.
                    class Pinned:
                        async def request(_, method, url, **kwargs):
                            return await network.request_ip(method, url, item["connect_ip"], **kwargs)
                    probe_network = Pinned()
                else:
                    probe_network = network
                if authority(response.url) != authority(item["url"]):
                    item["patch_evidence"] = {"status": "INCONCLUSIVE", "reason": "Redirected endpoint: enter final URL for patch collection."}
                    if options.active_check:
                        item["active"] = {"status": "SKIPPED", "reason_code": "CROSS_ORIGIN_REDIRECT",
                                          "reason": "This address redirected to another site; no active POST was sent."}
                elif options.active_check:
                    if passive_decisive(item):
                        item["active"] = {"status": "SKIPPED_PASSIVE", "reason": "An unambiguous upstream fixed PHP version was reported; active requests were unnecessary."}
                        if options.collect_patch_evidence:
                            item["patch_evidence"] = await collect_patch_evidence(probe_network, response.url, response)
                            merge_diagnostic_version(item, item["patch_evidence"])
                    elif 200 <= response.status < 400:
                        patch = await collect_patch_evidence(probe_network, response.url, response)
                        item["patch_evidence"] = patch
                        merge_diagnostic_version(item, patch)
                        if passive_decisive(item):
                            item["active"] = {"status": "SKIPPED_AFTER_DIAGNOSTIC", "reason": "A diagnostic page reported an upstream fixed PHP version; no multipart POST was sent.",
                                              "patch_evidence": patch, "cves": {c: "NOT_CONFIRMED" for c in CVES}}
                        else:
                            php_candidate = item["php"] in ("DETECTED", "LIKELY")
                            final = urlsplit(response.url)
                            probe_key = (final.scheme, final.hostname,
                                         final.port or (443 if final.scheme == "https" else 80),
                                         item["connect_ip"], "full" if php_candidate else "session_only")
                            async with active_lock:
                                if probe_key in active_probed:
                                    checked_at = active_probed[probe_key]
                                    item["active"] = {"status": "SKIPPED", "reason_code": "ALREADY_CHECKED",
                                                      "checked_at": checked_at,
                                                      "reason": f"Active requests already ran at {checked_at} for this destination/backend. This address was not retested."}
                                else:
                                    active_probed[probe_key] = response.url
                                    wordpress = any(tech.get("name") == "WordPress"
                                                    for tech in item.get("technologies", []))
                                    item["active"] = await collect_active_evidence(probe_network, response.url, response,
                                                                                    patch, wordpress_login=wordpress,
                                                                                    allow_oom=php_candidate)
                                    if any(e.get("type") == "session_warning_probe" and
                                           e.get("shape") in ("unpatched", "patched")
                                           for e in item["active"].get("evidence", [])):
                                        item["php"] = "DETECTED"
                                        item["confidence"] = "high"
                                        item["evidence"].append({"type": "active_session_warning",
                                                                 "source": "small multipart POST",
                                                                 "value": "PHP session start-up warnings observed",
                                                                 "strength": "strong", "url": response.url})
                    else:
                        item["active"] = {"status": "SKIPPED", "reason_code": "BASELINE_HTTP_ERROR",
                                          "reason": f"The page returned HTTP {response.status}; no active POST was sent."}
                        if options.collect_patch_evidence:
                            item["patch_evidence"] = await collect_patch_evidence(probe_network, response.url, response)
                            merge_diagnostic_version(item, item["patch_evidence"])
                else:
                    item["patch_evidence"] = await collect_patch_evidence(probe_network, response.url, response)
                    merge_diagnostic_version(item, item["patch_evidence"])
            item["verdict"], item["verdict_reason"] = triage_assessment(item)
            return item

        async def worker():
            nonlocal completed
            while not queue.empty():
                await control.checkpoint()
                try:
                    item = queue.get_nowait().copy()
                except asyncio.QueueEmpty:
                    return
                try:
                    response = await (network.request_ip("GET", item["url"], item["connect_ip"]) if item["connect_ip"] else network.request("GET", item["url"]))
                    await inspect_response(item, response)
                    if options.crawl and response.status == 200:
                        pages, report = await crawl_pages(network, response, options.max_pages, item["connect_ip"])
                        item["crawl"] = report
                        coverage["crawl_partial"] += int(report["partial"])
                        for page in pages:
                            from hunter.models import Target
                            child = pending_asset(page.url, Target(item["host"]), item["ips"], ["application crawl"], item["connect_ip"])
                            if child["id"] in unique:
                                continue
                            unique.add(child["id"])
                            await inspect_response(child, page, check=False)
                            emit({"type": "asset", "asset": child})
                except Stopped:
                    raise
                except Exception as exc:
                    message = f"{type(exc).__name__}: {str(exc)[:350]}"
                    tls_error = "CERTIFICATE_VERIFY_FAILED" in message or "certificate verify failed" in message
                    item.update(php="NOT_ESTABLISHED", assessment="TLS_VERIFICATION_FAILED" if tls_error else "UNREACHABLE", error=message, observed_at=utc_now())
                    coverage["http_errors"] += 1
                    if tls_error:
                        coverage["tls_errors"] += 1
                        # Certificate-only inspection; never silently disables HTTPS verification.
                        item["tls"] = await inspect_tls(item["url"], options.timeout, item["connect_ip"])
                completed += 1
                emit({"type": "asset", "asset": item})
                emit({"type": "progress", "completed": completed, "total": total, "current": item["id"]})
        await gather_workers(*(worker() for _ in range(min(options.concurrency, max(1, total)))))
        emit({"type": "finished", "status": "COMPLETED", "finished_at": utc_now(), "completed": completed, "coverage": coverage})
    except Stopped:
        emit({"type": "finished", "status": "STOPPED", "finished_at": utc_now(), "completed": completed, "coverage": coverage})
    except Exception as exc:
        emit({"type": "log", "message": f"Scan failed: {type(exc).__name__}: {exc}"})
        emit({"type": "finished", "status": "FAILED", "finished_at": utc_now(), "completed": completed, "coverage": coverage})
    finally:
        await network.close()
