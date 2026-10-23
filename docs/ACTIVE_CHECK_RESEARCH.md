# PHP2Shell active-check research — 2026-10-23

The active check now first looks for a patch-specific difference in PHP's
session upload-progress path. It sends a small invalid-session request twice,
with fresh IDs, and counts only PHP startup warning types. Official PHP
8.2.34/35, 8.3.35/36, 8.4.26/27 and 8.5.11/12 Windows builds were tested with
the production collector: each pre-fix build produced the extra session-write
warning; each fixed build did not. The change corresponds to the new failure
check before session flush in the [8.4.27 session source](https://raw.githubusercontent.com/php/php-src/PHP-8.4.27/ext/session/session.c)
compared with [8.4.26](https://raw.githubusercontent.com/php/php-src/PHP-8.4.26/ext/session/session.c).
The extra warning is evidence of an unpatched path, so a repeated result can
produce **Vulnerable**. It does not execute an exploit chain or demonstrate
memory corruption. Hidden warnings, disabled upload progress or a blocked POST
make the check inconclusive; an ordinary OOM remains non-specific.

The [PortSwigger PHP2Shell detection write-up](https://portswigger.net/blog/php2shell-x-burp-suite-detection-in-your-hands-within-a-day-of-disclosure)
and its [active Bambda](https://github.com/PortSwigger/bambdas/blob/main/CustomScanChecks/CVE-2026-109618CVE-2026-109619-PHP2Shell.bambda)
use the same three-warning session-path differential: the extra write warning
is the positive signal. This independently corroborates our small check but
does not supply a separate vulnerability oracle. We expanded the existing
opt-in check to previously unidentified PHP sites and to complete warning
sequences returned with HTTP errors. Such sites receive only the small request;
the new routing behavior has mocked-response coverage, not a new matched PHP
build matrix. A silent or blocked response stays inconclusive.

The [zarguell scanner research](https://github.com/zarguell/php2shell-scanner/blob/main/docs/RESEARCH.md)
adds one useful, low-impact routing idea: a WordPress front page can hide PHP
output while `/wp-login.php` executes PHP. An authorized five-origin comparison
confirmed this distinction on one site: root gave no warning pattern, the login
path gave the post-fix two-warning pattern twice. Radar now checks that path on
recognized WordPress sites when root is silent. It is a second place to apply
the same calibrated oracle, not a new vulnerability signature. Other reviewed
scanners still infer `upload_progress` from HTTP 200 or mark generic OOM/worker
failure as positive; matched patched builds can show those behaviors too.

Official local PHP 7.4.33 and 8.1.34 controls exposed an important boundary.
The 7.4 build showed no invalid-session warning in this test. The 8.1 build
printed three phrases with an older `Unknown:` prefix, whereas the production
oracle recognizes the 8.2–8.5 `PHP Request Startup:` wording. No patched 8.1
control was available, so Radar leaves that legacy form inconclusive rather
than calling it a validated positive.

| Public candidate | Actual observable | Decision |
| --- | --- | --- |
| [Ademking Nuclei CVE-2026-109618 template](https://github.com/Ademking/php2shell-nuclei-templates/blob/main/templates/php2shell/CVE-2026-109618.yaml) | Single invalid-session-ID warning. | A single warning is rejected: both pre-fix and fixed PHP emit it. The implemented check requires the extra session-write warning, repeated with a fresh ID. |
| [EthicalHCOP Simple Checker](https://github.com/EthicalHCOP/php2shell-Simple-Checker/blob/main/probe.py), [0xrsydn scanner](https://github.com/0xrsydn/php2shell-scan) | Multipart/upload-progress reachability and response or worker-failure profiles. | Reachability also occurs on patched PHP. Large-size and worker-death probes violate the requested impact limit. |
| [AbelLykens checker](https://github.com/AbelLykens/php2shell-checker) | Version banners and blocking of inert multipart requests. It explicitly avoids the vulnerable code path. | Useful exposure context, not a CVE test. |
| [JoasASantos scanner](https://github.com/JoasASantos/php2shell-scanner/blob/main/php2shell_scan.py) | Version evidence plus an optional large multipart instability probe. | Version-only or generic worker failure; the latter may cause DoS. |
| [Ademking handler-mismatch template](https://github.com/Ademking/php2shell-nuclei-templates/blob/main/templates/php2shell/php2shell-handler-mismatch.yaml) and [session-injection/LFI template](https://github.com/Ademking/php2shell-nuclei-templates/blob/main/templates/php2shell/php2shell-session-injection-lfi.yaml) | Session serialization mismatch, or session-file injection followed by application LFI. | Requires special application configuration/weakness; writes state. It does not isolate the vendor's OOM or stale-global defect. |
| [syrex1013 PoC](https://github.com/syrex1013/php2shell/blob/master/poc.py), [junaire exploit](https://github.com/junaire/CVE-2026-109618-exploit/blob/main/exploit.py) | Application-specific session-file inclusion or object gadget execution. | Executes attacker-controlled code or commands; outside the accepted scope. |
| [dinosn lab PoC](https://github.com/dinosn/php-cve-2026-10961x-lab-poc) | Demonstrated memory-corruption chains. | Specific to the defect, but the proof uses memory disclosure, controlled memory corruption and code execution. It is not suitable as a production diagnostic. |

The [PHP OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
ties CVE-2026-109618 to an OOM bailout leaving invalid request state for shutdown.
The [stale-global advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
requires a producer, persistent worker and pre-initialization consumer across
requests for CVE-2026-109619. Mere multipart acceptance or a session warning
does not establish either sequence.

## Reproducible local rejection

Run `.venv\Scripts\python.exe scripts/validate_nonproof_probes.py` after
`scripts/fetch_php_lab.py`. It starts only local official PHP 8.4.26 and 8.4.27
CLI servers. Requests are small and contain no PHP payload, memory-pressure body
or external target. Temporary session files are removed. The resulting
`artifacts/php-lab/nonproof-probes.json` shows, on **both** builds:

- invalid-session-ID warning: `true`;
- normal upload-progress marker in a session file: `true`.

The second observation is expected upload-progress functionality documented by
the [PHP manual](https://www.php.net/manual/en/session.upload-progress.php).
The script deliberately enables progress persistence to inspect the local marker.
The CLI-server result does not validate Apache or FPM behavior, but a positive
signal on the patched control is enough to reject these observables as general
positive CVE signatures. The older eight-configuration SID comparison is in
[VALIDATION.md](VALIDATION.md).

The later session-write warning now supplies a reproducible observable tied to
the official source change. The GUI uses it for the positive **Vulnerable** label
when there is no conflicting version or patch-feature evidence. The label means
an unpatched session path was observed, not that remote code execution succeeded.

## Re-review with a single worker crash allowed (2026-10-22)

The operator expanded the acceptable impact to a bounded worker crash. That
changes which experiments may be considered, but it does not make an HTTP 5xx,
timeout, or ordinary OOM message a CVE-specific result. A crashed worker can
drop its in-flight request; on small pools or during repeated scans it can
affect other users.

| Candidate | Finding after comparing the mechanism with the PHP advisories | Decision |
| --- | --- | --- |
| [Is4yev `splat.py`](https://github.com/Is4yev/php2shell-poc/blob/main/splat.py) | Claims a concurrent `session_start()` frees an upload-progress HashTable and calls any 500/502/503 or timeout a likely UAF. The claimed root cause does not match the published OOM-bailout or cross-request stale-global mechanisms. It does not demonstrate a patched/unpatched control. | Reject as a CVE-specific oracle. |
| [O3 crash checker claim](https://www.reddit.com/r/PHP/comments/1xcih9v/php2shell_versionchecking_misses_most_vulnerable/) | Calls the PHP memory-exhaustion fatal error a `VULNERABLE` signal. The vendor's own [next-request regression test](https://github.com/php/php-src/blob/PHP-8.4.27/sapi/cli/tests/oom_request_parsing_next_request.phpt) expects that fatal on patched PHP. | Reject the fatal message as a positive oracle. |
| [0xrsydn failure profiler](https://github.com/0xrsydn/php2shell-scan) | Documents 438 requests on 8.4.19 and 120 on 8.4.26 without a worker death. It explicitly says its profile cannot prove a patch. | Useful for reachability or before/after monitoring, not direct verification. |
| [Bhavye-Malhotra fatal-backtrace PoC](https://github.com/Bhavye-Malhotra/php2shell-2026) | Reports 4/4 segfaults against PHP 8.5.11 Apache/mod_php with `fatal_error_backtraces` and a pre-init INI diagnostic, versus 0/4 control. This matches one vendor-described CVE-2026-109619 chain, but depends on PHP 8.5, SAPI, and configuration; source and patched-build comparison were unavailable here. | Candidate for a separate isolated Apache 8.5.11/8.5.12 validation; not yet a general scanner. |
| [Bhavye-Malhotra remote detector](https://github.com/Bhavye-Malhotra/php2shell-2026/blob/master/detector/detect_remote.py) | Sends about 5 MB of multipart filenames, up to two OOM attempts, then treats a same-session-ID follow-up timeout as a leaked lock. A distinct-session control and matched patched/unpatched multi-worker comparison are not shown. The cited [vendor regression test](https://github.com/php/php-src/blob/PHP-8.4.27/tests/basic/oom_rfc1867_upload_progress.phpt) still expects OOM fatals on fixed PHP. | The lock hypothesis is worth isolated validation, but the remote timeout alone can also reflect application locking, overload, routing or proxy behavior. Do not promote it to a production CVE verdict. |
| [xuehuolll remote chain](https://github.com/xuehuolll/php2shell-CVE-2026-109618-109619) | Uses memory disclosure and a crafted fake HashTable to obtain command execution. | Defect-specific but outside the scanner's no-code-execution/no-disclosure boundary. |
| [ikow OOM trigger](https://github.com/ikow/php2shell-poc/blob/main/poc/verify_oom_trigger.py) | Sends thousands of multipart headers or fields, or up to 128 MB of streamed data. It treats HTTP 500 or a dropped connection as an OOM/crash signal, without a matched patched-build control or a post-OOM corruption observable. | Reject as a vulnerability verdict: an OOM or worker exit can occur on fixed PHP, and the default request is too large for a bounded production check. A single worker crash being allowed does not make it diagnostic. |
| [ikow FPM stale-state verifier](https://github.com/ikow/php2shell-poc/blob/main/poc/verify_fpm_stale_state.py) | Exercises the vendor-described producer/consumer sequence, but requires a pre-seeded ~30 MB session file, a session-starting endpoint, a low memory limit and a one-worker static FPM pool. Its 502 fallback does not independently establish stale global state. | Mechanistically relevant in its configured lab, but those prerequisites cannot be assumed on arbitrary company assets; do not generalize its result into a remote scanner signature. |
| [ikow session-injection verifier](https://github.com/ikow/php2shell-poc/blob/main/poc/verify_session_injection.py) | Places PHP source text in an upload filename and checks for session-file persistence. | Outside the no-supplied-code requirement; ordinary session upload progress is not itself proof of either OOM/stale-state CVE. |

The local-only `scripts/validate_oom_oracle.py` reproduces the PHP regression
test's small-memory request on official Windows PHP 8.4.26 and 8.4.27. In
`artifacts/php-lab/oom-oracle.json`, **both** versions report the same OOM
fatal, return HTTP 200, and answer the following GET normally. This rejects
the OOM-text detector, not every possible crash differential. The CLI server
does not model Apache mod_php or FPM, so their worker behavior still needs a
matched, isolated pair before any production probe is added.

The local-only `scripts/validate_fastcgi_lock.py` also starts two persistent
FastCGI processes for each official Windows build and tests the suggested
same-session follow-up after a large upload-progress multipart request. With
4,000 file parts and a 4 MB PHP memory limit, the trigger connection reset on
**both** 8.4.26 and 8.4.27. The separate-worker follow-up returned normally
with both the same and a distinct session ID on both builds. The saved result
is `artifacts/php-lab/fastcgi-lock-oracle.json`. This limited FastCGI experiment
does not reproduce every FPM/mod_php condition, but it supplies no positive
patched/unpatched differential for a production lock-timeout detector.

## Implemented bounded OOM-path observations

The opt-in mode now uses three request-parser mechanisms named in the [PHP OOM
advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w):
many headers **inside one multipart part**, then nested names on empty file
controls, then repeated session-upload-progress updates across file parts.
The third route follows the input shape in PHP's
[upload-progress regression test](https://github.com/php/php-src/blob/PHP-8.4.27/tests/basic/oom_rfc1867_upload_progress.phpt)
and uses a fresh random form session ID. Each request body is at most 2.6 MB.
It sends no PHP source, command, object gadget or malformed memory pointer. The scan sends
at most one sequence per host/backend and serializes these sequences globally.
It stops after an OOM text, HTTP 5xx, rejection, throttling or transport error,
then makes one recovery GET. No further stress request follows an anomaly.

The `OOM_OBSERVED` result is only a parser-pressure observation. Even literal
OOM text does not distinguish the patched from unpatched defect in general:
the [PHP regression test](https://github.com/php/php-src/blob/PHP-8.4.27/tests/basic/oom_rfc1867_upload_progress.phpt)
still expects an OOM on a fixed build. The second CVE additionally requires a
cross-request stale-state consumer; these probes do not attempt one. Network
blocking, memory limits, application behavior and different SAPIs can change
the outcome. Consequently **Fixed version** and **At risk** remain version-evidence labels, **Unconfirmed** covers missing or conflicting evidence, and **Vulnerable** requires the repeated pre-fix session-path behavior described above.

`scripts/validate_bounded_oom_lab.py` runs these exact bodies only against local
official Windows PHP CLI-server builds with a 4 MB memory limit. The saved
`artifacts/php-lab/bounded-oom-lab.json` records that the 2.3 MB part-header
probe produced OOM text on 8.4.26 but a normal response on 8.4.27 in that one
configuration. The 2.26 MB nested-empty-file and 0.50 MB session-progress
probes returned normally on both. With upload-progress cleanup disabled in the
isolated lab, the latter created one session file on each version, confirming
that PHP's progress handler ran. It was not a patched/unpatched differential.
This differential is promising as a lab observation, but is not a calibrated
remote oracle: the same patched build OOMs under another low-memory request in
`oom-oracle.json`, and production memory limits/SAPIs differ.

## Length-only session-cookie observation (2026-10-23)

The operator clarified that Radar need not show or retain any bytes from a
possible memory disclosure. The existing opt-in active requests now record only
the length of a `PHPSESSID` cookie in their responses. A new cookie at least
1024 characters long and at least 512 characters longer than the baseline is
reported as an anomaly; remaining pressure requests are skipped and the cookie
jar is cleared before recovery. Raw cookie values are not placed in the asset,
journal or export, and both CVEs remain `NOT_CONFIRMED`.

The new progress probe exercises one entry mechanism used by the
[TryHackMe room](https://tryhackme.com/room/cvephp2shell), but it does **not**
reproduce the leak stage in that room or the
[9bie laboratory chain](https://github.com/9bie/php2shell-bypass-aslr-exp).
That stage depends on a specific mod_php worker, heap layout, memory limit and
cross-request sequence. The local Windows CLI-server controls cannot validate
that sequence. `scripts/validate_cookie_length_lab.py` measured a normal
32-character PHP session ID on both 8.4.26 and 8.4.27. The bounded part-header
request caused OOM on 8.4.26 without an oversized cookie; 8.4.27 responded
normally. These observations confirm the length-only recording behavior, not a
vulnerability oracle. A future defect-specific detector would require matched
pre/post-patch Apache mod_php validation before being used for a positive CVE
verdict.
