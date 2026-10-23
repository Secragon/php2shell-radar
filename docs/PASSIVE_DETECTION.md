# Passive PHP recognition

The standard PHP recognition reads existing HTTP responses. It does not submit
forms, execute JavaScript, trigger memory errors or require phpinfo. The Windows
app now enables read-only diagnostic-page requests at first launch; users can
turn them off independently. Application crawling and active POST checks remain
opt-in settings.

## Evidence

- Strong: PHP runtime banners, selected diagnostic headers, structured phpinfo
  already present in a requested response, PHP-style diagnostics including HTML
  formatted messages. Strong public signals mean `DETECTED`, not authenticated
  runtime verification.
- Medium: PHPSESSID; framework/application cookie names; selected CMS headers.
  Cookie values and diagnostic filesystem paths are never exported.
- Weak: PHP-family path extensions, same-host HTML resource and form-action paths,
  quoted `.php` URLs in inline scripts, generator metadata, selected inline Drupal
  script assignments. These imply probable PHP without
  identifying a runtime version. Scripts are inspected as text, never executed.

Generator recognition covers WordPress, Drupal, Joomla, TYPO3, PrestaShop,
Magento, Moodle, MediaWiki, OpenCart, Nextcloud, ownCloud, Craft CMS, Grav and
Contao, PHP-Nuke and PHPBoost. Cookie/resource/header/DOM recognition also includes Laravel, Symfony,
CakePHP, CodeIgniter, phpBB, phpMyAdmin, PHPFusion, phpwcms and 1C-Bitrix. This is a curated PHP-focused
rule set, not the complete Wappalyzer database.

HTML is parsed structurally, respecting resource resolution and base URLs.
Comments and markup inside scripts/templates do not supply HTML fingerprints.
Foreign resource hosts and different custom ports do not supply local evidence;
this conservative policy can miss resources served from a legitimate CDN.
Only URL paths count for extension matching; query/fragment contents do not.
JSON/binary bodies are not interpreted as HTML.

## Attribution and versions

Bounded intermediate redirect responses remain in memory until fingerprinting.
Saved `response_observations` contain selected evidence, status, URL, technology
names/versions and truncation state, not raw response bodies or cookie values.
`included_in_assessment` identifies observations contributing to the entered
service's result. HTTP/HTTPS default-port upgrades on the same hostname can
contribute together; other hostnames and custom ports remain separate.

Foreign redirect destinations are recorded for context, but their banners never
mark the original host as PHP or patched. Conflicting PHP versions within a
response or across contributing redirects produce `UNKNOWN`. CMS versions are
stored under `technologies`, never used as PHP versions or CVE evidence.

Confidence (`high`, `medium`, `low`, `none`) follows the strongest evidence class;
these are not calibrated accuracy percentages. Multiple weak patterns do not
automatically become verified runtime evidence. Truncated input is explicitly
marked `detection_partial`; a negative result cannot establish PHP absence.

## Validation

Regression tests include HTML errors, generator attributes in different orders,
external resources, base URLs, PHP paths in query strings, legacy extensions,
framework cookies, sensitive-value omission, multiple banner versions, HTTPS
upgrades, external redirects and standard scans making no diagnostic-page probes.
Network tests use mock transports or localhost. They validate these cases, not
population-wide detection accuracy or a PHP2Shell vulnerability trigger.

## Comparison references

Rules here are independently written. The comparison consulted these public
sources; it does not claim parity with the commercial Wappalyzer database:

- [Wappalyzer public schema documentation](https://github.com/ahrefs/Wappalyzer)
- [WebAppAnalyzer PHP rules](https://github.com/enthec/webappanalyzer/blob/main/src/technologies/p.json)
- [WhatWeb PHP plugin](https://github.com/urbanadventurer/WhatWeb/blob/master/plugins/php.rb)
- [WhatWeb WordPress plugin](https://github.com/urbanadventurer/WhatWeb/blob/master/plugins/wordpress.rb)

The public WebAppAnalyzer PHP rule's specific signals—`PHPSESSID`, PHP runtime
headers, `.php` form actions, inline-script URLs and URL paths—are covered. The
broader CMS/framework hints add PHP-presence evidence. Neither that rule nor
this scanner can recover a hidden exact PHP patch version from an ordinary page
without a version-bearing response. This comparison does not imply parity with
Wappalyzer's full technology catalog or browser-side DOM/JavaScript execution.
