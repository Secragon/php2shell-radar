# PHP2Shell Radar

Python / PySide6 desktop inventory for **CVE-2026-109618 / CVE-2026-109619**.

The opt-in active check uses a small, patch-specific PHP session warning
comparison. Repeated pre-fix behavior produces **Vulnerable**; matched official
fixed builds do not produce that warning. A single invalid-session warning is
insufficient because both sides of the fix emit it. When warnings are unavailable,
Radar can still collect optional phpinfo evidence and run bounded parser-pressure
checks, but an OOM or worker failure alone is not a positive result. The check
identifies an unpatched code path; it does not execute an exploit or prove
memory corruption, complete remediation, or exploitability.
See [validation](VALIDATION.md) for the reproducible evidence and limitations.
The [active-check candidate review](ACTIVE_CHECK_RESEARCH.md) compares
public checkers/PoCs with the official defect descriptions and two local controls.
Discovery checks are bounded and verify public hostname candidates against DNS
and HTTP responses; see the discovery options below.

## Windows app

Download or copy the single `PHP2Shell Radar.exe` file from `release/` and
double-click it. No installer, Python installation, or console window is needed.
The app and its bundled DNS name list are contained in the EXE. Saved sessions
are stored in the current user's Windows application-data directory. If that
location is not writable, the app creates `PHP2Shell-Radar-data` beside the EXE.
Sessions saved under the previous application name remain available.
If neither location is writable, scan results can still be exported manually.
Exports go wherever you choose.

To rebuild the Windows EXE from source on a Windows machine with Python 3.11+:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[build-windows]"
.venv\Scripts\python.exe scripts\build_windows.py
```

The distributable is always `release/PHP2Shell Radar.exe`. Rebuilding updates that same file. The `build/` directory and
virtual environment are only build inputs; they are not needed to run it.

## Run from source

Python **3.11+**, Windows/Linux/macOS:

```sh
python -m venv .venv
# Windows:
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m hunter
# Linux/macOS:
.venv/bin/python -m pip install -e .
.venv/bin/python -m hunter
```

To build the portable Linux archive on Linux, install `.[build-linux]` and run
`python scripts/build_linux.py`. The archive is written to `release/`. A Windows
machine cannot cross-compile it; the Linux build must be tested on Linux before
publication. macOS packaging still needs platform testing.
Restart an already open app to load source changes.

## Discovery options

The Windows app starts with public subdomain discovery, the generic 100-name DNS
check, TLS certificate names and read-only PHP diagnostic pages enabled. Bare
domains use 80/443; explicit URLs preserve protocol, port, path and query. These
lightweight options can each be turned off. Additional ports, deeper DNS, page
crawling, every-IP checks and active PHP POST checks require explicit opt-in.

| Option | Implementation and limits |
| --- | --- |
| Public subdomain discovery | crt.sh + Cert Spotter (maximum 50 pages), HackerTarget Hostsearch (public 500-line cap), Subdomain Center (anonymous 500-name cap), IP.THC.ORG (up to five pages / 500 names), and same-domain links on the entered site's homepage (first 512 KiB, maximum 1000 links). crt.sh gets one retry after a transport failure. Provider errors, truncation and caps are logged as partial. Public names are validated with current DNS and HTTP checks. No external executable or API key is required. |
| Active DNS | 100 editable names. A/AAAA resolution, canonical CNAME names, one retry for transient errors. Distinct timeout, NXDOMAIN, NODATA, SERVFAIL and REFUSED states. |
| Recursive DNS | One additional level: maximum 20 resolved non-wildcard parents × the first 50 names. |
| Wildcard analysis | Three random DNS names identify wildcard IPs. Radar checks TCP reachability once per wildcard IP/port, avoiding repeated HTTP attempts where the port cannot be reached. It also compares HTTP/HTTPS pages, including shared error pages, at one random name with every resolved candidate under that root. Exact templates are compared after replacing an echoed request hostname, so host-specific placeholder text does not create false sites. A candidate serving the same page and PHP/server fingerprint is kept in the journal but excluded from site results; distinct content or headers remain eligible. This handles rotating CDN addresses, where a DNS IP mismatch alone does not prove a separate website. The heuristic does not prove that every virtual host was found. |
| TLS names | SAN names from the entered domain's HTTPS certificate, using its explicit HTTPS port if supplied; certificate metadata is read without trusting its identity. Matching subdomains are resolved. |
| CNAME candidates | Matching canonical names from DNS results are resolved in one additional batch. |
| Web ports | Ports 80 and 443 are always checked. Editable additional defaults: 8080, 8443, 8000, 8888, 3000, 5000, 8081, 9000. Both HTTP and HTTPS are attempted on nonstandard ports. |
| Every resolved IP | Each IPv4/IPv6 address is checked separately, preserving Host/SNI and separate report identities. Separate HTTP pools avoid cross-host TLS reuse on shared IPs. |
| Application paths | Bounded HTML-link, robots.txt and sitemap.xml exploration: maximum 12 visited URLs per endpoint. Same-authority GET requests; no form submission or query/action-link exploration. HTTP can still have application side effects. |

Unresolved and historical candidates stay visible as `DNS_UNRESOLVED`; they are
not described as live applications. Wildcard candidates remain marked ambiguous.
Redirects outside the entered domain scope are logged but excluded from site results.
An HTTP 200 response with an empty body and no PHP evidence, or a generic HTTP
error other than 401/403 with only weak PHP hints, is kept in the journal but does
not establish a website.
HTTP requests use a browser-compatible,
product-identified User-Agent so servers can return the page visitors receive.
Source coverage messages, unresolved counts, HTTP/TLS errors and partial crawling
are saved with the session. Neither CT nor the configured discovery methods can
guarantee complete asset coverage. No sibling-domain or IP-range enumeration is
performed automatically.

## PHP and PHP2Shell assessment

Standard recognition uses headers, cookie names, parsed HTML resource paths,
PHP-family extensions, HTML/plain-text PHP diagnostics, generator metadata and
CMS/framework hints (including WordPress, Drupal, Joomla, Laravel and others).
It requires no public phpinfo page. Redirects within a supplied domain's scope
are assessed as the final site (for example, an alias that redirects to another
subdomain); out-of-scope destinations cannot determine the entered site's PHP assessment.
External resources and PHP paths embedded only in query strings are excluded.
Application versions remain separate from observed PHP runtime versions.
Application hints can come from cached/static content and are weaker than runtime
signals. Missing signals mean `NOT_ESTABLISHED`, not "not PHP". Conflicting PHP
versions remain unknown. Confidence labels describe signal strength, not measured
probabilities. See [passive detection](PASSIVE_DETECTION.md).

Optional **Read optional PHP diagnostic pages** reads `phpinfo.php` and `info.php`
relative to the supplied application URL, plus the already obtained response.
Only a reported PHP version and selected INI rows are retained. A structured
`memory_hard_limit_percent` row is recorded as `PATCH_FEATURE_OBSERVED`, including
its valid default `no value`.
It is associated with the OOM fix, but cannot certify the complete stale-state
fix, all workers, vendor patch completeness, or authenticity of public output.

The optional diagnostic collector sends **GET requests only**, with no supplied
PHP/OS commands, multipart POST, shell payload, OOM or memory-corruption trigger.
Existing phpinfo output may be unavailable, blocked, stale or spoofed. Absence
is inconclusive. Its `patch_evidence` result keeps **both CVEs `NOT_CONFIRMED`**.

The opt-in **active check** first uses the passive result. An unambiguous
upstream fixed PHP version skips active traffic from this option. An older
reported version still receives the check because a vendor may have backported
the fix. On a reachable PHP endpoint it reads optional diagnostic pages, then
sends one small multipart request with a fresh, invalid session ID and upload
progress field. A recognizable PHP warning pattern is checked once more with
another fresh ID. The extra session-write warning identifies the pre-fix code
path; its absence alongside the two expected startup warnings identifies the
post-fix behavior. The whole active collector was compared with matched official
Windows PHP 8.2, 8.3, 8.4 and 8.5 builds on both sides of the fix. The response
body and session ID are not saved. When passive evidence does not identify PHP,
the active option runs only this small request: visible startup warnings can
identify a hidden PHP site, while a silent response leaves it undiscovered.
The warning sequence can be recognized even if the POST returns an HTTP error.
This check requires visible PHP warnings and enabled upload progress; otherwise
it is inconclusive. On recognized WordPress
sites, a silent front page leads to a read-only GET and the same small check on
`wp-login.php`, which executes PHP directly. This path recovered a repeatable
post-fix warning pattern on an authorized production WordPress site where `/`
showed none; it does not imply every worker is patched. If no warning pattern is
visible on either path, an endpoint already identified as PHP can receive up to
three bounded multipart POSTs per host/backend. A site with no PHP evidence
never receives these memory-pressure requests. They use many part headers,
nested empty file controls and PHP
session upload progress.
The latter uses a new random session ID in a form field. Each body is
capped at 2.6 MB, requests are serialized across the scan, and any OOM/5xx/
rejection/transport error stops the remaining probes. One GET then checks whether
the endpoint responds. These requests intentionally exercise OOM paths described
by PHP, so they can interrupt a worker, an in-flight request, or briefly affect
users. They contain no executable code. A normal response, OOM, 5xx, timeout,
or worker crash is **not** direct CVE confirmation; patched PHP can also OOM.
The upload-progress method can create temporary server-side session data.
Previously seen cookies are excluded from all active requests and the recovery GET.
The active check also records only the **length** of any `PHPSESSID` returned
by its baseline, probe and recovery responses. A new value of at least 1024
characters and at least 512 characters longer than the baseline is shown as a
cookie-length anomaly. The value is never saved in a finding, journal or export,
and an anomalous cookie is removed from the request client's jar before the
recovery GET. This is opportunistic response telemetry. The upload-progress
request exercises an early mechanism in the TryHackMe chain, **not** its
memory-leak exploit stage or a direct CVE confirmation; an application can also
set a long cookie for unrelated reasons.
Restoring an old session never silently re-enables the option.

The rightmost result column has four possible, color-coded labels: **Fixed version**
for a reported upstream fixed PHP version, **At risk** for a reported older version,
**Unconfirmed** when PHP evidence or patch level is uncertain, and **Vulnerable**
when two active requests reproduce the pre-fix session behavior without conflicting
patch evidence. This confirms an unpatched code path, not successful exploitation
or code execution. OOM, connection failure and cookie anomalies alone never produce
**Vulnerable**. INI settings and per-CVE evidence remain in technical details.
Open a result for its evidence and limitations.
An explicit older PHP version remains **At risk** when a proxy is present or the
response body is truncated; neither condition negates the version header. A
conflicting post-fix active signal remains **Unconfirmed**. Restored sessions
recalculate these labels from their saved evidence.

| HTTP/build result | Meaning |
| --- | --- |
| `POTENTIALLY_AFFECTED` | Reported version predates upstream fix; vendor backports may apply. |
| `FIXED_VERSION_REPORTED` | Public response claims an upstream fixed version; runtime not authenticated. |
| `BUILD_VERIFICATION_REQUIRED` | Vendor/prerelease suffix requires full revision assessment. |
| `UNKNOWN` | Insufficient or conflicting evidence. |
| `DNS_UNRESOLVED` | Candidate retained; no HTTP request attempted. Inspect DNS statuses. |
| `TLS_VERIFICATION_FAILED` | HTTPS verification failed; certificate-only inspection distinguishes an observed TLS service from HTTP availability. No silent TLS-verification bypass. |
| `UNREACHABLE` | HTTP operation failed; no CVE inference. |
| `NOT_TESTED` | Scan ended before the endpoint completed. |

Upstream baselines verified on **2026-10-22**: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
Minimal source backports also exist for 7.4 / 8.0 / 8.1. The table is bundled,
not automatically updated; Linux vendor backports require vendor build evidence.

## Reports and controls

During a scan, the results table shows only sites with detected or likely PHP evidence.
The light counter shows PHP sites / all reached websites and updates as HTTP checks finish;
DNS-only candidates and unreachable addresses are excluded. After a completed scan,
**Show other sites** adds reached websites without PHP indicators below the PHP results,
without vulnerability labels or colors. Lack of a public PHP indicator does not rule out PHP.
Pages on the same reached origin appear as one result, even when aliases redirect
to different paths. Redirecting HTTP aliases appear under their HTTPS destination.
Direct HTTP/HTTPS and apex/`www` variants appear in a dropdown when their
public page content identifies them as one website. A bounded HTML text sketch
also covers truncated responses and minor dynamic changes. Similar layout alone
does not merge two sites: the pages must also share a title or the full canonical
URL, including its path. Distinctly different pages remain separate. Host aliases
with the same complete page body and a title
identifying their shared destination fold only within the same input domain scope.
Redirecting hostnames are listed beneath their destination; protocol-only HTTP to
HTTPS upgrades are omitted from that list. HTTP 401 and 403 responses remain reached
sites; their HTTP/HTTPS views group only when the complete response bodies match.
Generic error pages do not create another site when a healthy
variant was reached. Checked addresses
and reached pages remain in saved session data; grouped PHP findings also show
their checked addresses in details. DNS candidates stay in scan progress and
saved session data; they do not appear as findings before PHP recognition. Double-click a
row for evidence, DNS, backend IP and per-CVE details. Hover over
or click an option's `?` for a plain-language explanation. The More options
window shows additional settings together without scrolling. Public subdomain,
common-name and TLS-name discovery, plus read-only diagnostic collection, are on
at first launch. More intensive options and the active PHP check are off. The status strip below the results
shows the current task; its Journal button opens a wide, resizable activity log
on the right. Pause prevents new operations at checkpoints;
in-flight work may finish. Stop preserves partial results. Closing during a scan
requests cancellation and closes after the worker exits.

SQLite sessions use Qt's per-user application-data directory and retain technical
scan data for later inspection. JSON and CSV exports contain only the six displayed
columns and rows currently visible in the results table. Search, expanded
addresses and Show other sites affect the export; the journal and technical
metadata are excluded.
No raw response bodies or session cookie values are saved. URL queries are saved:
avoid entering secrets in URLs. Storage is local and unencrypted. Starting from
a saved session repeats its configuration as a new run; automatic diffs are not
implemented. Existing sessions remain readable.

Default concurrency: 8; HTTP timeout: 7 seconds; per-host minimum interval: 350 ms.
Detection body cap: 128 KiB; patch collection: 512 KB; CT response: 2 MB.
HTTP 429 stops the applicable collector/crawl; automatic HTTP retries are not used.
DNS uses the system resolver to preserve corporate/split-DNS visibility.

## Test

```sh
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite covers discovery pagination, partial coverage, DNS status/retry handling,
wildcard preservation, backend identity/Host/SNI, bounded crawling, certificate
inspection, result classification, controls, SQLite/exports and GUI integration.
All network tests use mock transports or localhost, never third-party assets.

The separate real-PHP matrix is described in [docs/VALIDATION.md](VALIDATION.md).

## Primary references

- [PHP OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Official fix](https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065)
- [Cert Spotter pagination](https://sslmate.com/help/reference/ct_search_api_v1)
- [Subdomain Center API](https://github.com/ARPSyndicate/docs)
- [IP.THC.ORG subdomain lookup API](https://ip.thc.org/docs/API/subdomain-lookup)
- [OWASP application-entry discovery](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points/)
