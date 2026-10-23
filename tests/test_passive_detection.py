"""Passive fingerprint regressions and request-level redirect attribution."""
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from hunter.detection import fingerprint
from hunter.discovery import DNSResult
from hunter.engine import Control, run_scan
from hunter.models import ScanOptions, Target
from hunter.network import Network, Response


def detect(body="", headers=None, url="https://a.test/", status=200):
    return fingerprint(Response(url, status, headers or {}, body, 1))


class PassiveDetectionTests(unittest.TestCase):
    def test_html_runtime_errors_and_no_sensitive_path_saved(self):
        for body in (
            '<b>Warning</b>: Undefined variable in <b>/private/SECRET/index.php</b> on line <b>12</b>',
            'PHP Fatal error: Uncaught Error in /private/SECRET/index.php:12\nStack trace:\n in /private/SECRET/index.php on line 12',
            'Parse error: unexpected token in /private/SECRET/index.php on line 3',
            'Warning: undefined variable in C:\\Program Files\\SECRET\\index.phtml on line 12',
        ):
            with self.subTest(body=body):
                result = detect(body)
                self.assertEqual(result['php'], 'DETECTED')
                self.assertNotIn('SECRET', json.dumps(result))
                self.assertEqual(result['assessment'], 'UNKNOWN')
        for body in ('Warning: this product expires on line 12', '<!-- Warning: fail in /a.php on line 3 -->',
                     '<script>const example="Warning: fail in /a.php on line 3";</script>'):
            self.assertEqual(detect(body)['php'], 'NOT_ESTABLISHED')

    def test_structured_meta_and_app_version_never_becomes_php_version(self):
        for name in ('WordPress 6.8', 'Drupal 11', 'Joomla! - Open Source CMS', 'TYPO3 CMS 13.4',
                     'PrestaShop 8.2', 'Magento', 'Moodle', 'MediaWiki 1.43', 'OpenCart',
                     'Nextcloud', 'ownCloud', 'Craft CMS', 'Grav', 'Contao',
                     'PHP-Nuke', 'PHPBoost'):
            with self.subTest(name=name):
                result = detect(f"<META content='{name}' data-x='y' NAME='generator'>")
                self.assertEqual(result['php'], 'LIKELY')
                self.assertEqual(result['assessment'], 'UNKNOWN')
                self.assertIsNone(result['version'])
                self.assertTrue(result['technologies'])
        result = detect('<meta name="generator" content="WordPress 6.8">', {'X-Powered-By': 'PHP/8.4.26'})
        self.assertEqual(result['version'], '8.4.26')
        self.assertEqual(result['technologies'][0]['versions'], ['6.8'])
        for body in ('<!-- <meta name="generator" content="WordPress"> -->',
                     '<meta name><meta name="generator" content><a href="https://[bad/">bad</a>',
                     '<script>const html=\'<meta name="generator" content="WordPress">\';</script>',
                     '<template><meta name="generator" content="WordPress"></template>'):
            self.assertEqual(detect(body)['php'], 'NOT_ESTABLISHED')

    def test_extensions_use_path_not_query(self):
        for ext in ('php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps'):
            self.assertEqual(detect(url=f'https://a.test/index.{ext}/path?x=1')['php'], 'LIKELY')
        for url in ('https://a.test/?next=https://other.test/index.php', 'https://a.test/index.php.jpg',
                    'https://a.test/#/index.php'):
            self.assertEqual(detect(url=url)['php'], 'NOT_ESTABLISHED')

    def test_resources_are_parsed_resolved_and_attributed(self):
        for body in ("<form action = '/upload.PHP?x=1'></form>",
                     '<script SRC="/wp-content/a.js"></script>',
                     '<base href="/portal/"><a href="login.phtml">Login</a>',
                     '<link href="https://a.test/wp-includes/a.css" rel="stylesheet">'):
            self.assertEqual(detect(body)['php'], 'LIKELY')
        for body in ('<img src="https://other.test/wp-content/a.png">',
                     '<a href="https://other.test/login.php">external</a>',
                     '<base href="https://other.test/"><script src="wp-content/a.js"></script>',
                     '<!-- <script src="/wp-content/a.js"></script> -->',
                     '<a href="/?next=/index.php">next</a>',
                     '<a href="https://a.test:8443/index.php">other service</a>',
                     '<a href="https://[bad/">bad</a>'):
            with self.subTest(body=body):
                self.assertEqual(detect(body)['php'], 'NOT_ESTABLISHED')
        for path, name in (('/core/misc/drupal.js', 'Drupal'), ('/media/system/js/core.js', 'Joomla'),
                           ('/static/version123/frontend/a.js', 'Magento'), ('/bitrix/js/core.js', '1C-Bitrix'),
                           ('/theme/styles.php', 'Moodle'), ('/phpmyadmin/style.css', 'phpMyAdmin')):
            self.assertIn(name, [t['name'] for t in detect(f'<script src="{path}"></script>')['technologies']])

    def test_public_wappalyzer_php_signals_without_phpinfo(self):
        for body in ('<form action="login_process.php"></form>',
                     '<form action="/assets/mail.php"></form>',
                     '<script>fetch("/api/process.php?send=1")</script>',
                     '<script src="/assets/process.php"></script>'):
            with self.subTest(body=body):
                result = detect(body)
                self.assertEqual(result['php'], 'LIKELY')
                self.assertIsNone(result['version'])
        self.assertEqual(detect(headers={'Set-Cookie': 'PHPSESSID=SECRET'})['php'], 'LIKELY')
        self.assertEqual(detect(headers={'Server': 'nginx PHP/8.4.27'})['version'], '8.4.27')
        for body in ('<script>fetch("https://other.test/a.php")</script>',
                     '<script>const x="/?file=index.php"</script>',
                     '<script>const x="/a.php.jpg"</script>'):
            self.assertEqual(detect(body)['php'], 'NOT_ESTABLISHED')
        for body in ('<div class="phpbb_copyright">x</div>',
                     '<table class="forumline">x</table>',
                     '<meta name="copyright" content="phpBB Group">'):
            self.assertIn('phpBB', [t['name'] for t in detect(body)['technologies']])
        self.assertIn('phpMyAdmin', [t['name'] for t in detect(headers={'Set-Cookie': 'phpMyAdmin_https=SECRET'})['technologies']])

    def test_cookies_headers_and_inline_rules(self):
        for cookie, name in (('laravel_session', 'Laravel'), ('wordpress_logged_in_abc', 'WordPress'),
                             ('SSESS' + 'a' * 32, 'Drupal'), ('PrestaShop-abc', 'PrestaShop'),
                             ('phpbb3_abc', 'phpBB'), ('CAKEPHP', 'CakePHP'), ('ci_session', 'CodeIgniter'),
                             ('sf_redirect', 'Symfony'), ('X-Magento-Vary', 'Magento'), ('BITRIX_SM', '1C-Bitrix')):
            result = detect(headers={'Set-Cookie': f'other=x; Path=/, {cookie}=SECRET; HttpOnly; Path=/'})
            self.assertIn(name, [t['name'] for t in result['technologies']])
            self.assertEqual(result['confidence'], 'medium')
            self.assertNotIn('SECRET', json.dumps(result))
        for headers in ({'PHP Warning': 'SECRET'}, {'PHP': 'Error parsing SECRET on line 12'}):
            result = detect(headers=headers)
            self.assertEqual(result['php'], 'DETECTED')
            self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(detect('<script>window.drupalSettings = {};</script>')['php'], 'LIKELY')
        self.assertEqual(detect(headers={'Link': '<https://a.test/wp-json/>; rel="https://api.w.org/"'})['php'], 'LIKELY')
        self.assertEqual(detect(headers={'Link': '<https://other.test/wp-json/>; rel="https://api.w.org/"'})['php'], 'NOT_ESTABLISHED')
        self.assertEqual(detect(headers={'X-Drupal-Cache': 'HIT'})['php'], 'LIKELY')

    def test_version_conflicts_and_no_runtime_version_from_apps(self):
        result = detect(headers={'X-Powered-By': 'PHP/8.4.26, PHP/8.4.27'})
        self.assertEqual(result['reported_versions'], ['8.4.26', '8.4.27'])
        self.assertEqual(result['assessment'], 'UNKNOWN')
        self.assertIsNone(result['version'])
        self.assertEqual(detect(headers={'X-Powered-By': 'PHP/8.3.6-0ubuntu0.24.04.13'})['assessment'], 'BUILD_VERIFICATION_REQUIRED')
        fusion = detect(headers={'X-Powered-By': 'PHPFusion 9.0'})
        self.assertEqual(fusion['php'], 'LIKELY')
        self.assertIsNone(fusion['version'])
        self.assertEqual(detect(headers={'X-Powered-By': 'PHP'})['php'], 'DETECTED')
        self.assertIsNone(detect(headers={'X-Powered-By': 'PHP/8.4'})['version'])

    def test_phpinfo_is_optional_and_json_markup_is_not_html(self):
        body = '<title>phpinfo()</title><h1>PHP Version 8.4.27</h1><h2>Configuration</h2>'
        self.assertEqual(detect(body)['version'], '8.4.27')
        self.assertEqual(detect(body, {'Content-Type': 'application/json'})['php'], 'NOT_ESTABLISHED')
        result = fingerprint(Response('https://a.test/', 200, {}, 'partial', 1, truncated=True))
        self.assertTrue(result['detection_partial'])


class RedirectDetectionTests(unittest.IsolatedAsyncioTestCase):
    async def fetch(self, handler, url='http://a.test/', scope_hosts=()):
        network = Network(ScanOptions([Target('a.test')], interval=0), Control(), httpx.MockTransport(handler))
        try:
            return fingerprint(await network.request('GET', url), scope_hosts)
        finally:
            await network.close()

    async def test_intermediate_headers_cookies_survive_https_upgrade(self):
        def handler(request):
            if request.url.scheme == 'http':
                return httpx.Response(302, headers={'Location': 'https://a.test/', 'Set-Cookie': 'PHPSESSID=SECRET; Path=/', 'X-Powered-By': 'PHP/8.4.26'})
            return httpx.Response(200, text='plain final')
        result = await self.fetch(handler)
        self.assertEqual(result['php'], 'DETECTED')
        self.assertEqual(result['version'], '8.4.26')
        self.assertEqual(len(result['response_observations']), 2)
        self.assertEqual(result['evidence'][0]['http_status'], 302)
        self.assertNotIn('SECRET', json.dumps(result))

    async def test_foreign_target_cannot_mark_original_php_or_fixed(self):
        def handler(request):
            if request.url.host == 'a.test':
                return httpx.Response(302, headers={'Location': 'https://login.other.test/', 'Set-Cookie': 'PHPSESSID=SECRET'})
            return httpx.Response(200, headers={'X-Powered-By': 'PHP/8.4.27'}, text='final')
        result = await self.fetch(handler)
        self.assertEqual(result['php'], 'LIKELY')
        self.assertEqual(result['assessment'], 'UNKNOWN')
        self.assertIsNone(result['version'])
        self.assertFalse(result['response_observations'][-1]['included_in_assessment'])
        self.assertEqual(result['response_observations'][-1]['reported_versions'], ['8.4.27'])

    async def test_redirect_within_supplied_domain_identifies_final_site(self):
        def handler(request):
            if request.url.host == 'dostavka.a.test':
                return httpx.Response(301, headers={'Location': 'https://delivery.a.test/'})
            return httpx.Response(200, text='<meta name="generator" content="WordPress 6.8">')
        result = await self.fetch(handler, 'https://dostavka.a.test/', ('a.test',))
        self.assertEqual(result['php'], 'LIKELY')
        self.assertEqual(result['site_url'], 'https://delivery.a.test/')
        self.assertEqual(result['technologies'][0]['name'], 'WordPress')
        self.assertFalse(result['response_observations'][0]['included_in_assessment'])
        self.assertTrue(result['response_observations'][1]['included_in_assessment'])

    async def test_redirect_outside_supplied_domain_stays_unattributed(self):
        def handler(request):
            if request.url.host == 'dostavka.a.test':
                return httpx.Response(301, headers={'Location': 'https://delivery.other.test/'})
            return httpx.Response(200, text='<meta name="generator" content="WordPress 6.8">')
        result = await self.fetch(handler, 'https://dostavka.a.test/', ('a.test',))
        self.assertEqual(result['php'], 'NOT_ESTABLISHED')
        self.assertEqual(result['site_url'], 'https://dostavka.a.test/')

    async def test_www_to_apex_uses_explicit_www_target(self):
        def handler(request):
            if request.url.host == 'www.a.test':
                return httpx.Response(301, headers={'Location': 'https://a.test/'})
            return httpx.Response(200, text='<meta name="generator" content="WordPress">')
        result = await self.fetch(handler, 'https://www.a.test/', ('www.a.test',))
        self.assertEqual(result['php'], 'LIKELY')
        self.assertEqual(result['site_url'], 'https://a.test/')

    async def test_same_host_redirect_version_conflict(self):
        def handler(request):
            if request.url.path == '/':
                return httpx.Response(302, headers={'Location': '/end', 'X-Powered-By': 'PHP/8.4.26'})
            return httpx.Response(200, headers={'X-Powered-By': 'PHP/8.4.27'})
        result = await self.fetch(handler)
        self.assertEqual(result['assessment'], 'UNKNOWN')
        self.assertEqual(result['reported_versions'], ['8.4.26', '8.4.27'])

    async def test_default_passive_requests_no_diagnostic_pages_or_posts(self):
        requests, events = [], []
        def handler(request):
            requests.append((request.method, request.url.path))
            return httpx.Response(200, text='<meta name="generator" content="WordPress 6.8">')
        options = ScanOptions([Target('a.test', 'https://a.test/')], interval=0)
        with patch('hunter.engine.resolve_details', new=AsyncMock(return_value=DNSResult({'127.0.0.1'}, {'A': 'OK'}))):
            await run_scan(options, Control(), events.append, httpx.MockTransport(handler))
        self.assertEqual(requests, [('GET', '/')])
        asset = [e['asset'] for e in events if e['type'] == 'asset'][-1]
        self.assertEqual(asset['php'], 'LIKELY')
        self.assertEqual(asset['active']['status'], 'NOT_RUN')
        self.assertNotIn('patch_evidence', asset)

    async def test_scan_attributes_in_scope_redirect_to_final_wordpress_site(self):
        requests, events = [], []
        def handler(request):
            requests.append((request.method, str(request.url)))
            if request.url.host == 'restaurant.test':
                return httpx.Response(301, headers={'Location': 'https://delivery.restaurant.test/'})
            return httpx.Response(200, text='<meta name="generator" content="WordPress">')
        options = ScanOptions([Target('restaurant.test', 'https://restaurant.test/')], interval=0)
        with patch('hunter.engine.resolve_details', new=AsyncMock(return_value=DNSResult({'127.0.0.1'}, {'A': 'OK'}))):
            await run_scan(options, Control(), events.append, httpx.MockTransport(handler))
        asset = [e['asset'] for e in events if e['type'] == 'asset'][-1]
        self.assertEqual(asset['php'], 'LIKELY')
        self.assertEqual(asset['site_url'], 'https://delivery.restaurant.test/')
        self.assertEqual(asset['active']['status'], 'NOT_RUN')
        self.assertEqual(len(requests), 2)

    async def test_active_option_uses_only_small_oracle_when_php_not_established(self):
        requests, events = [], []
        def handler(request):
            requests.append((request.method, request.url.path, len(request.content)))
            return httpx.Response(200)
        options = ScanOptions([Target('a.test', 'https://a.test/')], interval=0, active_check=True)
        with patch('hunter.engine.resolve_details', new=AsyncMock(return_value=DNSResult({'127.0.0.1'}, {'A': 'OK'}))):
            await run_scan(options, Control(), events.append, httpx.MockTransport(handler))
        self.assertEqual([(method, path) for method, path, _ in requests],
                         [('GET', '/'), ('GET', '/phpinfo.php'), ('GET', '/info.php'), ('POST', '/')])
        self.assertLess(requests[-1][2], 1024)
        asset = [e['asset'] for e in events if e['type'] == 'asset'][-1]
        self.assertEqual(asset['active']['status'], 'INCONCLUSIVE')
        self.assertEqual(asset['php'], 'NOT_ESTABLISHED')
        self.assertEqual(asset['patch_evidence']['status'], 'INCONCLUSIVE')
