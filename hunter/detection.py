"""Passive response fingerprints. No probes, JS execution or inferred PHP versions."""
from html.parser import HTMLParser
import hashlib
import re
from urllib.parse import urljoin, urlsplit

from hunter.models import ADVISORIES, CVES, utc_now, version_assessment
from hunter.site_identity import describe_site


PHP_PATH = re.compile(r"\.(?:php[34578]?|phtml|phps)(?:/|$)", re.I)
SCRIPT_PHP_URL = re.compile(r"[\"']([^\"'\s<>]{1,300}\.(?:php[34578]?|phtml)(?:[/?#][^\"'\s<>]*)?)[\"']", re.I)
PHP_VERSION = re.compile(r"\bPHP\s*/?\s*(\d+\.\d+\.\d+(?:[-+~.a-zA-Z0-9]*)?)", re.I)
PROXIES = (("Cloudflare", "cf-ray"), ("CloudFront", "x-amz-cf-id"),
           ("Varnish", "x-varnish"), ("Fastly", "x-served-by"),
           ("Sucuri", "x-sucuri-id"), ("Imperva", "x-iinfo"))
# Independently maintained rules. CMS versions are never PHP runtime versions.
GENERATORS = (
    ("WordPress", r"^WordPress(?:\s+([\w.+-]+))?(?:$|[ ;])"),
    ("Drupal", r"^Drupal(?:\s+([\w.+-]+))?(?:$|[ ;(])"),
    ("Joomla", r"^Joomla!?"), ("TYPO3", r"^TYPO3(?: CMS)?(?:\s+([\d.]+))?"),
    ("PrestaShop", r"^PrestaShop(?:\s+([\d.]+))?"),
    ("Magento", r"^Magento"), ("Moodle", r"^Moodle"),
    ("MediaWiki", r"^MediaWiki(?:\s+([\d.]+))?"),
    ("OpenCart", r"^OpenCart"), ("Nextcloud", r"^Nextcloud"),
    ("ownCloud", r"^ownCloud"), ("Craft CMS", r"^Craft CMS"),
    ("Grav", r"^Grav(?:CMS)?"), ("Contao", r"^Contao"),
    ("PHP-Nuke", r"^PHP-Nuke"), ("PHPBoost", r"^PHPBoost$"),
)
COOKIE_PRODUCTS = (
    ("Laravel", r"^laravel_session$"), ("WordPress", r"^wordpress_(?:logged_in_|sec_|test_cookie$)"),
    ("Drupal", r"^S?SESS[0-9a-f]{32}$"), ("PrestaShop", r"^PrestaShop-"),
    ("phpBB", r"^phpbb(?:\d*_.*)?$"), ("CakePHP", r"^CAKEPHP$"),
    ("CodeIgniter", r"^ci_session$"), ("Symfony", r"^sf_redirect$"),
    ("Magento", r"^X-Magento-Vary$"), ("1C-Bitrix", r"^BITRIX_"),
    ("phpMyAdmin", r"^phpMyAdmin(?:_https)?$"),
)
RESOURCE_PRODUCTS = (
    ("WordPress", r"/(?:wp-content|wp-includes|wp-json)/"),
    ("Drupal", r"/(?:sites/(?:default|all)/(?:files|modules|themes)|core/(?:misc|modules|themes))/"),
    ("Joomla", r"/media/(?:system|jui|com_joomla)/"),
    ("Magento", r"/static/(?:version\d+/)?frontend/"),
    ("1C-Bitrix", r"/bitrix/(?:js|templates|components)/"),
    ("Moodle", r"/(?:theme/(?:styles|image)|lib/javascript)\.php(?:/|$)"),
    ("phpMyAdmin", r"/phpmyadmin(?:/|$)"),
)


def authority(url):
    """Default HTTP-to-HTTPS upgrades share identity; custom ports stay separate."""
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return (p.hostname or "").lower(), None if port in (80, 443) else port


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resources, self.meta, self.text, self.scripts = [], [], [], []
        self.base = None
        self.hidden = None
        self.dom_hints = set()

    def handle_starttag(self, tag, attrs):
        if self.hidden:
            return
        attrs = dict(attrs)
        if tag == "base" and self.base is None:
            self.base = attrs.get("href")
        if tag in ("script", "style", "template"):
            self.hidden = tag
        if tag == "meta":
            self.meta.append(((attrs.get("name") or "").lower(), attrs.get("content") or ""))
        if tag == "div" and "phpbb_copyright" in (attrs.get("class") or "").lower():
            self.dom_hints.add("phpBB")
        if tag == "table" and "forumline" in (attrs.get("class") or "").lower():
            self.dom_hints.add("phpBB")
        keys = {"a": ("href",), "link": ("href",), "script": ("src",),
                "img": ("src",), "form": ("action",), "iframe": ("src",)}.get(tag, ())
        self.resources.extend(attrs[k] for k in keys if attrs.get(k))

    def handle_endtag(self, tag):
        if tag == self.hidden:
            self.hidden = None

    def handle_data(self, data):
        if self.hidden == "script":
            self.scripts.append(data)
        elif not self.hidden:
            self.text.append(data)


def observe(response):
    """Return selected evidence, never raw cookies or page contents."""
    evidence, versions, technologies = [], set(), {}
    headers = {k.lower(): v for k, v in response.headers.items()}

    def add(kind, source, value, strength, technology=None, app_version=None):
        item = {"type": kind, "source": source, "value": value,
                "strength": strength, "url": response.url, "http_status": response.status}
        if technology:
            item["technology"] = technology
            entry = technologies.setdefault(technology, {"name": technology, "versions": set(), "implies": "PHP"})
            if app_version:
                entry["versions"].add(app_version)
        if item not in evidence:
            evidence.append(item)

    def product(name, source, strength="weak", app_version=None):
        add("application", source, f"{name} fingerprint; PHP inferred, runtime unverified",
            strength, name, app_version)

    for key in ("x-powered-by", "server"):
        value = headers.get(key, "")
        # PHPFusion or a URL containing /php/ is not a PHP runtime banner.
        if re.search(r"(?:^|[\s,;(])PHP(?:$|[\s/;,)]|\d)", value, re.I):
            add("header", key, value[:500], "strong")
            versions.update(m.group(1) for m in PHP_VERSION.finditer(value))
    for key in ("php", "php warning"):
        if key in headers and (key == "php warning" or re.search(r"Error parsing .+ on line \d+", headers[key], re.I)):
            add("error", key, "PHP diagnostic header (content omitted)", "strong")
    cookie_names = re.findall(r"(?:^|[,;]\s*)([!#$%&'*+.^_`|~\w-]+)=", headers.get("set-cookie", ""))
    for name in cookie_names:
        if name.lower() == "phpsessid":
            add("cookie", "set-cookie", "PHPSESSID cookie name (value omitted)", "medium")
        for product_name, pattern in COOKIE_PRODUCTS:
            if re.search(pattern, name, re.I):
                product(product_name, "cookie name (value omitted)", "medium")
    for key, pattern, name in (
        ("x-generator", r"\bDrupal\b", "Drupal"),
        ("x-drupal-cache", r"^(?:HIT|MISS)$", "Drupal"),
        ("x-drupal-dynamic-cache", r"^(?:HIT|MISS|UNCACHEABLE)$", "Drupal"),
        ("x-powered-by", r"^Laravel\b", "Laravel"),
        ("x-powered-by", r"^Craft CMS\b", "Craft CMS"),
        ("x-powered-cms", r"^Bitrix Site Manager\b", "1C-Bitrix"),
        ("x-phpfusion", r".+", "PHPFusion"),
        ("x-powered-by", r"^PHP(?:-)?Fusion\b", "PHPFusion"),
        ("x-phpwcms-release", r".+", "phpwcms"),
    ):
        if re.search(pattern, headers.get(key, ""), re.I):
            product(name, key, "medium")
    # Use the path, never query-string values, for extension fingerprints.
    if PHP_PATH.search(urlsplit(response.url).path):
        add("url", "path", "Requested path has a PHP-family extension", "weak")
    page = Page()
    content_type = headers.get("content-type", "").lower()
    if not content_type or "html" in content_type or "text/plain" in content_type:
        page.feed(response.text)
    visible = re.sub(r"\s+", " ", " ".join(page.text))
    if re.search(r"\b(?:PHP\s+)?(?:Fatal error|Warning|Parse error|Notice|Deprecated|Recoverable fatal error)\s*:\s*[^\n]{0,1500}?\bin\s+.{1,1000}?\.(?:php\d?|phtml)\b.*?\bon line\s+\d+", visible, re.I):
        add("error", "page text", "PHP-style runtime diagnostic (path/content omitted)", "strong")
    if "phpinfo()" in visible.lower() and "PHP Version" in visible and "Configuration" in visible:
        add("phpinfo", "page text", "Structured phpinfo-style output", "strong")
        match = re.search(r"PHP Version\s+(\d+\.\d+\.\d+[-+~.a-zA-Z0-9]*)", visible)
        if match:
            versions.add(match.group(1))
    try:
        base = urljoin(response.url, page.base or "")
    except ValueError:
        base = response.url
    # Wappalyzer's public PHP rule also recognizes .php URLs in inline scripts.
    # Only quoted URL-shaped literals are used, and foreign hosts are excluded.
    script_resources = [m.group(1) for script in page.scripts for m in SCRIPT_PHP_URL.finditer(script)]
    for resource in [*page.resources, *script_resources]:
        try:
            resolved = urljoin(base, resource)
            parsed = urlsplit(resolved)
            local = parsed.scheme in ("http", "https") and authority(resolved) == authority(response.url)
        except ValueError:
            continue
        if not local:
            continue
        path = parsed.path
        if PHP_PATH.search(path):
            source = "inline script URL" if resource in script_resources else "resource path"
            add("html", source, "Same-host URL has a PHP-family extension", "weak")
        for name, pattern in RESOURCE_PRODUCTS:
            if re.search(pattern, path, re.I):
                product(name, "same-host resource path")
    for name, value in page.meta:
        if name == "generator":
            for product_name, pattern in GENERATORS:
                match = re.search(pattern, value, re.I)
                if match:
                    product(product_name, "meta generator", app_version=match.group(1) if match.lastindex else None)
        if name == "copyright" and re.search(r"^phpBB Group$", value, re.I):
            product("phpBB", "meta copyright")
    for name in page.dom_hints:
        product(name, "HTML class")
    # Inline source is inspected as text; scripts are never run or fetched.
    scripts = "\n".join(page.scripts)
    if re.search(r"\b(?:drupalSettings\s*=|Drupal\.settings\s*=)", scripts):
        product("Drupal", "inline script assignment")
    for match in re.finditer(r'<([^>]+)>;\s*rel=[\"\']?https://api\.w\.org/', headers.get("link", ""), re.I):
        try:
            local = authority(urljoin(response.url, match.group(1))) == authority(response.url)
        except ValueError:
            local = False
        if local:
            product("WordPress", "link header")
    return {"url": response.url, "http_status": response.status, "evidence": evidence,
            "reported_versions": sorted(versions), "technologies": [
                {**t, "versions": sorted(t["versions"])} for t in technologies.values()],
            "proxy": [name for name, marker in PROXIES if marker in headers],
            "truncated": response.truncated}


def in_scope(url, hosts):
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return any(host == root or host.endswith("." + root) or
               (root.startswith("www.") and host == root[4:]) for root in hosts)


def host_neutral_digest(response):
    """Hash a page template after replacing the requested hostname it echoes."""
    hostname = urlsplit(response.url).hostname
    if not hostname or response.status <= 0 or response.truncated:
        return None
    pattern = re.compile(re.escape(hostname), re.I)
    if not pattern.search(response.text):
        return None
    template = pattern.sub("{requested-host}", response.text)
    return hashlib.sha256(template.encode("utf-8")).hexdigest()


def fingerprint(response, scope_hosts=()):
    scope_hosts = tuple(scope_hosts)
    observations = [observe(hop) for hop in response.history] + [observe(response)]
    # A redirect into an explicitly supplied domain's scope identifies the final
    # site, not the alias that redirected to it. Foreign sites stay excluded.
    original = authority(observations[0]["url"])
    final = authority(response.url)
    final_in_scope = in_scope(response.url, scope_hosts)
    external_redirect = final != original and not final_in_scope
    target = final if final != original and final_in_scope else original
    for observation in observations:
        observation["included_in_assessment"] = authority(observation["url"]) == target
    owned = [o for o in observations if authority(o["url"]) == target]
    evidence = [e for o in owned for e in o["evidence"]]
    versions = sorted({v for o in owned for v in o["reported_versions"]})
    version = versions[0] if len(versions) == 1 else None
    assessment = version_assessment(version)
    if len(versions) > 1:
        assessment = {"status": "UNKNOWN", "reason": "Conflicting reported PHP versions; inspect each response's evidence."}
    technologies = {}
    for observation in owned:
        for tech in observation["technologies"]:
            technologies.setdefault(tech["name"], set()).update(tech["versions"])
    strong = any(e["strength"] == "strong" for e in evidence)
    medium = any(e["strength"] == "medium" for e in evidence)
    return {
        "observed_at": utc_now(), "final_url": response.url,
        "site_url": response.url if target == final and final != original else observations[0]["url"],
        "external_redirect": external_redirect,
        "content_sha256": hashlib.sha256(response.text.encode("utf-8")).hexdigest() if response.status > 0 and not response.truncated else None,
        "host_neutral_sha256": host_neutral_digest(response),
        "site_identity": describe_site(response),
        "http_status": response.status,
        "elapsed_ms": response.elapsed_ms, "php": "DETECTED" if strong else "LIKELY" if evidence else "NOT_ESTABLISHED",
        "confidence": "high" if strong else "medium" if medium else "low" if evidence else "none",
        "version": version, "reported_versions": versions,
        "technologies": [{"name": name, "versions": sorted(values), "implies": "PHP"} for name, values in sorted(technologies.items())],
        "proxy": sorted({p for o in owned for p in o["proxy"]}), "redirects": response.redirects,
        "response_observations": observations,
        "detection_partial": any(o["truncated"] for o in owned),
        "server": (response.headers.get("server", "")[:300] if authority(response.url) == target else ""),
        "evidence": evidence, "cves": {cve: dict(assessment) for cve in CVES},
        "assessment": assessment["status"], "active": {"status": "NOT_RUN"},
        "sources": ADVISORIES, "error": "",
    }
