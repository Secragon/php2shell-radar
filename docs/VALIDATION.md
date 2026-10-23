# Checker validation — 2026-10-23

## Actual result

The opt-in active check now recognizes a pre-fix PHP session code path without
executing code or reading session data. Two small invalid-session multipart
requests must independently produce the extra PHP session-write warning. This
pattern makes the user-facing result **Vulnerable** in the absence of conflicting
patch evidence. It indicates an unpatched path, not proven remote code execution
or a demonstration of memory corruption.

No universal remote observable was established from the reviewed primary
advisories and regression tests, even after allowing a bounded worker crash.
This does not make a crash an oracle. A memory-corruption trigger
can disrupt other requests even without RCE; worker death, generic errors or
timeouts alone cannot establish either CVE. See `ACTIVE_CHECK_RESEARCH.md` for
the crash-permitted re-review and local OOM control.

## Real PHP comparison

Official Windows NTS x64 releases were downloaded over HTTPS from
`downloads.php.net/~windows/releases/archives/`. SHA-256 values recorded for the
downloaded archives (provenance records, not a claim of signature verification):

| Build | SHA-256 |
| --- | --- |
| 8.4.26 | `da68394f9193b7f6b89d0c76861a4034ae10efee7fd55a7255d8118c2acf70d7` |
| 8.4.27 | `93bd8a815a52156606fb906d0573437908c61f96e2cc52c03a51e36a41bf5236` |

Each PHP CLI development server listened only on 127.0.0.1. The test app served
a static PHP baseline and a local phpinfo page. Each version was checked with
`display_errors` and `session.upload_progress.enabled` on/off: eight configurations.

| PHP | display_errors | upload_progress | Rejected SID warning | OOM patch feature |
| --- | --- | --- | --- | --- |
| 8.4.26 | Off | Off | No | Absent |
| 8.4.26 | Off | On | No | Absent |
| 8.4.26 | On | Off | No | Absent |
| 8.4.26 | On | On | **Yes** | Absent |
| 8.4.27 | Off | Off | No | Present |
| 8.4.27 | Off | On | No | Present |
| 8.4.27 | On | Off | No | Present |
| 8.4.27 | On | On | **Yes** | Present |

The single session-ID warning failed specificity: both pre-fix and fixed PHP
produced it. The new check looks for the **additional** session-write warning,
which appears only before the fix in the matched lab. Both warning types and
their ordering are checked; repeating the request reduces transient errors.

The production active collector was run against four official pre-fix/fixed
pairs: **8.2.34/35, 8.3.35/36, 8.4.26/27 and 8.5.11/12**. All eight builds
returned the expected `UNPATCHED_SESSION_PATH` or `PATCHED_SESSION_PATH`
status. The full matrix covered 64 local configurations: two warning-display
settings, two session-ID placements and two upload-progress settings per build.
With `display_errors` off or upload progress disabled the warnings were
not visible, so a remote scan must remain inconclusive. The comparisons use
Windows CLI servers on localhost; Apache, FPM, proxy rewriting and vendor
backports were not independently validated.

A separate 16-configuration local comparison of official PHP 7.4.33 and
8.1.34 found no visible invalid-session warning on 7.4.33. PHP 8.1.34 printed
the three phrases with an older `Unknown:` prefix, which the 8.2–8.5 oracle
does not mistake for a patched result. There is no matched vendor-backported
8.1 control, so this legacy format is not promoted to **Vulnerable**.

An authorized production WordPress comparison found that `/` concealed the
warning pattern while `/wp-login.php` displayed the post-fix two-warning
pattern twice. Radar now tries that dynamic path after a silent WordPress front
page, before bounded memory probes. This gives another observable path, but
the two-warning result alone does not verify the installed package or all
workers. The production comparison stored only response status, warning shape,
and short header metadata; it saved no body or cookie values.

Structured phpinfo output reported `memory_hard_limit_percent` only in 8.4.27,
including a `no value` default in both local/master columns. This validates the
**feature fingerprint on these two builds**, not exploitation, full remediation,
backports, Apache mod_php, FPM, CGI, other branches or other operating systems.
Feature presence and reported version are separate pieces of evidence. The
structured page parser also extracted the matching version from every one of
the eight local controls. The engine uses that version only when it does not
conflict with passive HTTP evidence.

## Reproduce

```powershell
.venv\Scripts\python.exe scripts/fetch_php_lab.py
.venv\Scripts\python.exe scripts/validate_php_lab.py
```

Downloads and generated test apps stay under ignored `artifacts/php-lab/`. Each
server is terminated in a finally block. The validation script asserts the
expected comparison and writes its full report to `artifacts/php-lab/validation.json`.
The production opt-in active collector first sends one or two small session
requests. If their warning pattern is unavailable, it may send three bounded multipart
memory-pressure requests after passive and diagnostic checks remain
inconclusive. They are globally serialized and stop on the first anomaly.
Run `scripts/validate_bounded_oom_lab.py` for a localhost-only comparison of
those exact bodies against 8.4.26 and 8.4.27. See
`ACTIVE_CHECK_RESEARCH.md` for its observations and why OOM alone cannot give a
direct CVE verdict. A **single** SID warning remains insufficient; the
additional session-write warning is the discriminating signal.

Run `scripts/validate_session_warning_oracle.py --quick 8.2.34 8.2.35 8.3.35 8.3.36 8.4.26 8.4.27 8.5.11 8.5.12`
after downloading those local builds to reproduce the complete collector
comparison. The JSON record is `artifacts/php-lab/session-warning-oracle.json`.

## Further validation needed for broader coverage

1. Map its observable to the affected lifetime/OOM operation in official source.
2. Reproduce on matched pre/post-patch builds with identical configuration.
3. Show the signal disappears with the specific fix, not just with hidden errors,
   disabled uploads, a different pool or WAF behavior.
4. Treat both CVEs separately. Include mod_php and FPM paths, multiple workers,
   different PHP branches and vendor backports before broad applicability claims.
5. Send no attacker PHP, OS command, shell, gadget chain or data-extraction payload.
6. Measure worker/process effects. A crash is not a sufficient generic oracle.
7. Preserve `INCONCLUSIVE` when the required path/observable cannot be established.

## Sources

- [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Official invalid-SID regression test still expects warnings in fixed source](https://raw.githubusercontent.com/php/php-src/31c0ea7d7ff1d1fccb6492e52dab544011628065/ext/session/tests/rfc1867_sid_invalid.phpt)
