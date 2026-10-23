PHP2Shell Radar 1.1.0 expands discovery and makes results easier to use.
Direct HTTP/HTTPS and apex/`www` views are grouped only when their public
pages support one website identity. Shared navigation alone cannot merge
different sites, and distinct canonical paths stay separate. Redirects and
equivalent host aliases appear under one result, while wildcard placeholder
pages and redirects outside the entered domain scope do not inflate the count.

Clicking a found website copies its displayed address and shows a small rounded
"Copied" message for one second. Double-clicking a PHP result still opens its details.
The Export results button is now below the table and becomes available after
a scan ends. JSON and CSV exports contain only the currently visible result
rows and six displayed columns, without the activity journal or technical
scan records. Search, expanded addresses and Show other sites determine which
rows are included.

Empty HTTP 200 responses and generic wildcard DNS/HTTP error pages do not
establish sites. The journal still records candidates that could not establish
a site. Public subdomain sources can be rate-limited, so discovery coverage is
reported as partial when a provider is unavailable.

The release includes a portable Windows GUI executable and a Linux x64 archive,
with SHA-256 checksums.

See the [README](https://github.com/Secragon/php2shell-radar#readme) for
installation, result meanings and assessment limits.
