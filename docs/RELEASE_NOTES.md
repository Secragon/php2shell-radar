PHP2Shell Radar 1.0.1 extends the existing Active check to websites whose PHP
runtime is hidden from passive fingerprinting. A small session-path request can
now identify PHP and distinguish the observed pre-fix warning pattern from the
post-fix pattern. The check also reads those warnings when the server responds
with an HTTP error status. Sites without prior PHP evidence never receive the
memory-pressure probes.

The interface still has one Active check option. Its help text explains the
additional coverage and when memory-pressure checks may run. An observed
post-fix warning pattern remains Unconfirmed because it does not establish the
patch state of every worker or both CVEs.

The release includes a portable Windows GUI executable and a Linux x64 archive,
with SHA-256 checksums.

See the [README](https://github.com/Secragon/php2shell-radar#readme) for
installation, result meanings and assessment limits.
