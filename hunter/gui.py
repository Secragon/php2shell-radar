import asyncio
from html import escape
from importlib.resources import files
import json
from pathlib import Path
import re
import sqlite3
import sys
from urllib.parse import urlsplit

from PySide6.QtCore import QEasingCurve, QPoint, QStandardPaths, Qt, QThread, QVariantAnimation, Signal
from PySide6.QtGui import QColor, QIcon
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QDoubleSpinBox, QFileDialog,
    QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QListWidget, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar,
    QPushButton, QSpinBox, QSplitter, QStyledItemDelegate, QTableWidget, QTableWidgetItem, QTextBrowser,
    QToolButton, QToolTip, QVBoxLayout, QWidget,
)

from hunter.engine import Control, pending_asset, run_scan
from hunter.models import ScanOptions, Target, WEB_PORTS, endpoints, parse_targets
from hunter.storage import Store, export_report


STYLE = """
QWidget { background: #f8fafc; color: #27313b; font-family: 'Segoe UI', sans-serif; font-size: 13px; }
QMainWindow { background: #f8fafc; }
QLabel#title { font-size: 24px; font-weight: 700; color: #242a32; }
QLabel#muted { color: #687785; }
QLabel#metric { font-size: 15px; font-weight: 550; color: #526477; }
QLabel#currentStatus { color: #455766; font-weight: 600; }
QGroupBox { background: #ffffff; border: 1px solid #e2e8ef; border-radius: 12px; margin-top: 12px; padding: 15px 12px 10px; font-weight: 650; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #344353; }
QPlainTextEdit, QLineEdit, QSpinBox, QDoubleSpinBox, QListWidget { background: #ffffff; border: 1px solid #d7e0ea; border-radius: 7px; padding: 6px; selection-background-color: #dbe7fa; }
QPlainTextEdit:focus, QLineEdit:focus { border-color: #8daed7; }
QPushButton { background: #eaf1fb; color: #314761; border: 1px solid #d4e1f0; padding: 7px 12px; border-radius: 7px; font-weight: 600; }
QPushButton:hover { background: #dce9f9; }
QPushButton:disabled { color: #a2adba; background: #f0f3f6; border-color: #e4e9ee; }
QPushButton#primary { background: #e62d4d; color: #ffffff; font-weight: 700; border: none; }
QPushButton#primary:hover { background: #cf2443; }
QPushButton#drawerButton { background: #f1f5fb; border-color: #dce5ef; }
QCheckBox { spacing: 7px; font-weight: 550; }
QCheckBox::indicator { width: 16px; height: 16px; }
QTableWidget { background: #ffffff; alternate-background-color: #f8fbff; border: 1px solid #e1e8f0; gridline-color: #edf1f5; selection-background-color: #e4efff; selection-color: #24384c; }
QHeaderView::section { background: #eef4fb; color: #526477; padding: 8px; border: none; font-weight: 650; }
QProgressBar { background: #e7edf5; border: none; border-radius: 3px; min-height: 6px; max-height: 6px; text-align: center; }
QProgressBar::chunk { background: #d72545; border-radius: 3px; }
QSplitter::handle { background: #edf1f5; height: 5px; }
QToolTip { background: #ffffff; color: #27313b; border: 1px solid #cbd8e7; padding: 8px; }
QToolButton#helpButton { background: #e7f2ff; color: #426892; border: 1px solid #c9dff4; border-radius: 11px; font-size: 12px; font-weight: 800; }
QToolButton#helpButton:hover { background: #cfe7ff; color: #214d78; border-color: #9cc8ed; }
QToolButton#helpButtonWarning { background: #fff0de; color: #a05b22; border: 1px solid #f4d5b2; border-radius: 11px; font-size: 12px; font-weight: 800; }
QToolButton#helpButtonWarning:hover { background: #ffe0ba; color: #824214; }
QWidget#advancedPane { background: #ffffff; }
QPushButton#advancedButton { background: #e4effb; color: #345c83; border-color: #c9ddf2; }
QPushButton#advancedButton:hover { background: #d5e8fb; }
"""


class ScanThread(QThread):
    event = Signal(dict)

    def __init__(self, options, parent=None):
        super().__init__(parent)
        self.options = options
        self.control = Control()

    def run(self):
        try:
            asyncio.run(run_scan(self.options, self.control, self.event.emit))
        except Exception as exc:
            self.event.emit({"type": "finished", "status": "FAILED", "error": str(exc)})


def muted(text):
    label = QLabel(text)
    label.setObjectName("muted")
    label.setWordWrap(True)
    return label


def help_html(description, impact):
    """A readable width for both clicked help and hover tooltips."""
    return ("<table width='360' cellspacing='0' cellpadding='0'><tr><td>"
            f"<b>What it does</b><br>{escape(description)}"
            f"<br><br><b>Impact</b><br>{escape(impact)}"
            "</td></tr></table>")


def result_group_key(asset):
    """Merge pages on the same destination site when their assessments agree."""
    final_url = asset.get("final_url")
    if final_url and asset.get("http_status") == 200:
        parsed = urlsplit(final_url)
        if parsed.hostname:
            return ("destination", parsed.scheme, parsed.hostname.lower(),
                    parsed.port or (443 if parsed.scheme == "https" else 80),
                    asset.get("php"), asset.get("version"),
                    tuple(asset.get("reported_versions") or ()), asset.get("assessment"),
                    asset.get("verdict"), tuple(asset.get("proxy") or ()),
                    asset.get("wildcard_ambiguous"), asset.get("detection_partial"),
                    asset.get("connect_ip"))
    digest = asset.get("content_sha256")
    if not digest or asset.get("detection_partial") or asset.get("http_status") != 200:
        return ("endpoint", asset.get("id", asset["url"]))
    parsed = urlsplit(asset.get("final_url") or asset.get("site_url") or asset["url"])
    host = (parsed.hostname or "").lower()
    if not host:
        return ("endpoint", asset.get("id", asset["url"]))
    return ("content", parsed.scheme, host.removeprefix("www."),
            parsed.port or (443 if parsed.scheme == "https" else 80), parsed.path or "/", parsed.query,
            digest, asset.get("php"), asset.get("version"),
            tuple(asset.get("reported_versions") or ()), asset.get("assessment"),
            asset.get("verdict"), asset.get("http_status"),
            tuple(asset.get("proxy") or ()), asset.get("wildcard_ambiguous"),
            asset.get("connect_ip"))


def result_preference(asset):
    """Prefer the direct HTTPS address for equivalent destinations."""
    display = result_address(asset)
    parsed = urlsplit(display)
    original = urlsplit(asset["url"])
    final = urlsplit(asset.get("final_url") or asset["url"])
    return (original.scheme != final.scheme, parsed.scheme != "https",
            (parsed.hostname or "").startswith("www."),
            asset["url"] != display, display)


def result_address(asset):
    """Show the HTTPS destination of an upgrade, even without a direct HTTPS input."""
    original = urlsplit(asset["url"])
    final = urlsplit(asset.get("final_url") or "")
    if (asset.get("http_status") == 200 and original.scheme == "http" and
            final.scheme == "https" and final.hostname):
        site_url = asset.get("site_url")
        return site_url if site_url and urlsplit(site_url).scheme == "https" else asset["final_url"]
    return asset.get("site_url") or asset["url"]


def preferred_active_asset(assets, members, representative):
    """Show the most informative active outcome of a merged destination."""
    priority = {"UNPATCHED_SESSION_PATH": 0, "SESSION_COOKIE_LENGTH_ANOMALY": 1,
                "PATCHED_SESSION_PATH": 2, "OOM_OBSERVED": 3,
                "NO_OOM_OBSERVED": 4, "OBSERVED": 4, "INCONCLUSIVE": 5}
    return min((assets[key] for key in members),
               key=lambda asset: (priority.get(asset.get("active", {}).get("status"), 99),
                                  asset is not representative, result_preference(asset)))


def protocol_pair_key(asset):
    """Pair successful default-port HTTP/HTTPS views of the same input site."""
    original = urlsplit(asset["url"])
    final = urlsplit(asset.get("final_url") or asset["url"])
    original_port = original.port or (443 if original.scheme == "https" else 80)
    final_port = final.port or (443 if final.scheme == "https" else 80)
    if (asset.get("http_status") != 200 or original.scheme != final.scheme or
            original.scheme not in ("http", "https") or not original.hostname or not final.hostname or
            original.hostname.removeprefix("www.") != final.hostname.removeprefix("www.") or
            original_port != (443 if original.scheme == "https" else 80) or
            final_port != (443 if final.scheme == "https" else 80)):
        return None
    return (original.hostname.removeprefix("www."), original.path or "/", original.query,
            asset.get("php"), asset.get("version"), asset.get("assessment"),
            asset.get("verdict"), asset.get("detection_partial"),
            tuple(asset.get("proxy") or ()), asset.get("wildcard_ambiguous"), asset.get("connect_ip"))


def site_identity_keys(asset):
    """Match a reached site across redirects and equivalent protocol or www views."""
    final = urlsplit(asset.get("final_url") or result_address(asset))
    if not final.hostname:
        return set()
    host = final.hostname.lower()
    port = final.port or (443 if final.scheme == "https" else 80)
    backend = asset.get("connect_ip")
    keys = {("destination", final.scheme, host, port, backend)}
    if asset.get("http_status") == 200 and port == (443 if final.scheme == "https" else 80):
        keys.add(("protocol", host, backend))
        digest = asset.get("content_sha256")
        if digest and not asset.get("detection_partial"):
            keys.add(("content", final.scheme, host.removeprefix("www."), port,
                      digest, backend))
    return keys


def result_layout(assets, expanded_pairs, php_only=True):
    """Return site rows, folding redirects and equivalent HTTP/HTTPS views."""
    groups = {}
    php_site_keys = set()
    if not php_only:
        for asset in assets.values():
            if asset.get("php") in ("DETECTED", "LIKELY"):
                php_site_keys.update(site_identity_keys(asset))
    for key, asset in assets.items():
        found_php = asset.get("php") in ("DETECTED", "LIKELY")
        if (found_php if php_only else
                not found_php and isinstance(asset.get("http_status"), int) and asset["http_status"] > 0
                and not site_identity_keys(asset).intersection(php_site_keys)):
            groups.setdefault(result_group_key(asset), []).append(key)

    # Preserve apex/www folding when their final URLs differ but content is identical.
    identical = {}
    for group_key, members in list(groups.items()):
        asset = assets[min(members, key=lambda key: result_preference(assets[key]))]
        digest = asset.get("content_sha256")
        if not digest or asset.get("detection_partial") or asset.get("http_status") != 200:
            continue
        final = urlsplit(asset.get("final_url") or result_address(asset))
        alias_key = (final.scheme, (final.hostname or "").removeprefix("www."),
                     final.port or (443 if final.scheme == "https" else 80),
                     final.path or "/", final.query, digest, asset.get("php"), asset.get("version"),
                     tuple(asset.get("reported_versions") or ()), asset.get("assessment"),
                     asset.get("verdict"), tuple(asset.get("proxy") or ()),
                     asset.get("wildcard_ambiguous"), asset.get("connect_ip"))
        if alias_key in identical:
            groups[identical[alias_key]].extend(members)
            del groups[group_key]
        else:
            identical[alias_key] = group_key

    representatives = {key: min(members, key=lambda member: result_preference(assets[member]))
                       for key, members in groups.items()}
    candidates = {}
    for group_key, representative in representatives.items():
        asset = assets[representative]
        pair_key = protocol_pair_key(asset)
        if pair_key is not None:
            candidates.setdefault(pair_key, {}).setdefault(urlsplit(asset["url"]).scheme, []).append(group_key)
    children = {}
    for pair_key, schemes in candidates.items():
        if len(schemes.get("http", [])) == 1 and len(schemes.get("https", [])) == 1:
            children[schemes["http"][0]] = (schemes["https"][0], ("protocol_pair", pair_key))
    child_keys = {child for child, _ in children.values()}
    order = {key: index for index, key in enumerate(groups)}
    roots = [key for key in groups if key not in child_keys]
    roots.sort(key=lambda key: min(order[key], order[children[key][0]]) if key in children else order[key])
    rows = []
    for key in roots:
        pair = children.get(key)
        search_members = groups[key] + groups[pair[0]] if pair else groups[key]
        rows.append((key, groups[key], pair[1] if pair else None, False, search_members))
        if pair and pair[1] in expanded_pairs:
            child_key = pair[0]
            rows.append((child_key, groups[child_key], None, True, groups[child_key]))
    return rows, len(roots)


def active_display(active, asset=None):
    """Keep scanner telemetry distinct from the version-based result column."""
    status = active.get("status", "NOT_RUN")
    reason = active.get("reason", "")
    if status == "NOT_RUN":
        return "Off", "Active checking was not enabled for this scan."
    if status in ("SKIPPED_PASSIVE", "SKIPPED_AFTER_DIAGNOSTIC"):
        return "Not needed", "An upstream fixed PHP version was reported before active POST requests were needed."
    if status == "UNPATCHED_SESSION_PATH":
        return "Patch gap found", ("Two small requests showed the pre-fix PHP session behavior. "
                                   "No code was run or data extracted; this identifies an unpatched code path, not RCE.")
    if status == "PATCHED_SESSION_PATH":
        return "Patch behavior", ("Two small requests showed the post-fix PHP session behavior. "
                                  "This does not prove that every worker or both CVE fixes are present.")
    if status == "SKIPPED":
        code = active.get("reason_code", "")
        if code == "ALREADY_CHECKED" or reason.startswith("One bounded probe sequence"):
            checked_at = active.get("checked_at")
            input_url = (asset or {}).get("url", "")
            final_url = (asset or {}).get("final_url", "")
            if input_url and final_url and urlsplit(input_url).scheme != urlsplit(final_url).scheme:
                origin_scheme = urlsplit(input_url).scheme.upper()
                destination_scheme = urlsplit(final_url).scheme.upper()
                return f"Redirects to {destination_scheme}", (
                    f"The {origin_scheme} address redirects to {destination_scheme}. Active requests ran at {checked_at}. "
                    f"No active POST was sent to the {origin_scheme} address." if checked_at else
                    f"The {origin_scheme} address redirects to {destination_scheme}. No active POST was sent to the input address.")
            return "Not retested", (f"No active POST was sent to this address. The same destination was tested at {checked_at}." if checked_at else
                                   "No active POST was sent to this address; the same destination was already tested.")
        if code == "BASELINE_HTTP_ERROR" or "baseline endpoint did not respond" in reason:
            http_status = (asset or {}).get("http_status")
            return "Page error", (f"The page returned HTTP {http_status}; no active POST was sent." if http_status else
                                  "The page did not respond successfully; no active POST was sent.")
        if code == "CROSS_ORIGIN_REDIRECT" or "Cross-origin redirect" in reason:
            return "Not checked", "This address redirected to another site, so no active POST was sent. Scan the destination directly."
        return "Not checked", reason or "No active POST was sent to this address."
    if status == "NO_OOM_OBSERVED":
        if active.get("recovery", {}).get("reachable") is False:
            return "Service issue", "The follow-up request failed after active checking. Review site health; this does not confirm either CVE."
        return "Checked", "Active requests returned ordinary responses and no memory error was seen. This does not verify that PHP is patched."
    if status == "OOM_OBSERVED":
        return "Memory error", "A memory exhaustion message appeared. This can occur with fixed or affected PHP and does not confirm either CVE."
    if status == "SESSION_COOKIE_LENGTH_ANOMALY":
        return "Anomaly found", "An unusually long PHP session cookie appeared after an active request. Only its length was kept; this does not confirm either CVE."
    if status == "INCONCLUSIVE":
        return "No result", reason or "The active check could not establish a result."
    if status == "OBSERVED":
        return "Checked", reason or "Active check completed."
    return status, reason or "See technical details."


def existing_file(path):
    try:
        return path.is_file()
    except OSError:
        return False


class ResultFadeDelegate(QStyledItemDelegate):
    """Fade a whole finding without changing its stored text or colors."""

    def __init__(self, window):
        super().__init__(window.table)
        self.window = window

    def paint(self, painter, option, index):
        painter.save()
        if index.row() < len(self.window.row_group_keys):
            key = self.window.row_group_keys[index.row()]
            painter.setOpacity(self.window.row_opacity.get(key, 1.0))
        super().paint(painter, option, index)
        painter.restore()


class MainWindow(QMainWindow):
    def __init__(self, store_path=None):
        super().__init__()
        self.setWindowTitle("PHP2Shell Radar")
        self.setWindowIcon(QIcon(str(files("hunter").joinpath("data/app-icon.png"))))
        self.resize(1280, 780)
        self.setMinimumSize(780, 560)
        self.thread = None
        self.close_requested = False
        self.run_record = {}
        self.assets = {}
        self.rows = {}
        self.row_members = {}
        self.row_search_members = {}
        self.row_group_keys = []
        self.expandable_rows = {}
        self.expanded_pairs = set()
        self.root_result_count = 0
        self.other_rows = {}
        self.other_search_members = {}
        self.other_expandable_rows = {}
        self.other_expanded_pairs = set()
        self.other_header_row = None
        self.other_result_count = 0
        self.row_opacity = {}
        self.row_fades = {}
        self.help_buttons = {}
        self.words = files("hunter").joinpath("data/subdomains.txt").read_text(encoding="utf-8").split()
        self.storage_failed = False
        self.storage_fallback = False
        if store_path:
            self.store = Store(store_path)
        else:
            location = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
            legacy = location.parent / "PHP2Shell Hunter" / "sessions.sqlite3"
            scanner = location.parent / "PHP2Shell Scanner" / "sessions.sqlite3"
            paths = [path for path in (legacy, scanner) if existing_file(path)]
            paths.append(location / "sessions.sqlite3")
            first_portable = len(paths)
            base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path.cwd()
            portable_legacy = base / "PHP2Shell-Hunter-data" / "sessions.sqlite3"
            portable_scanner = base / "PHP2Shell-Scanner-data" / "sessions.sqlite3"
            paths.extend(path for path in (portable_legacy, portable_scanner) if existing_file(path))
            paths.append(base / "PHP2Shell-Radar-data" / "sessions.sqlite3")
            for index, path in enumerate(paths):
                try:
                    self.store = Store(str(path))
                    self.storage_fallback = index >= first_portable
                    break
                except (OSError, sqlite3.Error):
                    continue
            else:
                self.store = Store(":memory:")
                self.storage_failed = True
        self.build_ui()
        if self.storage_failed:
            self.current_status.setText("Session history unavailable · export results to save them")
        elif self.storage_fallback:
            self.current_status.setText("Using portable session storage")

    def build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(8)
        top = QHBoxLayout()
        title = QLabel("PHP2Shell Radar")
        title.setObjectName("title")
        top.addWidget(title, 1)
        self.advanced_btn = QPushButton("More options  ↗")
        self.advanced_btn.setObjectName("advancedButton")
        self.advanced_btn.setToolTip("Open additional discovery and scan settings in one window. Lightweight discovery is on by default; more intensive checks are optional.")
        self.advanced_btn.clicked.connect(self.open_advanced)
        top.addWidget(self.advanced_btn)
        history = QPushButton("History")
        history.setToolTip("Open previous scans saved on this computer.")
        history.clicked.connect(self.open_history)
        top.addWidget(history)
        self.export_btn = QPushButton("Export")
        self.export_btn.setToolTip("Save the complete scan report, including checked sites without PHP evidence.")
        self.export_btn.clicked.connect(self.export)
        self.export_btn.setEnabled(False)
        top.addWidget(self.export_btn)
        root.addLayout(top)

        splitter = QSplitter(Qt.Orientation.Vertical)
        config = QWidget()
        grid = QGridLayout(config)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(10)
        target_group = QGroupBox("Domains and URLs")
        target_layout = QVBoxLayout(target_group)
        self.targets = QPlainTextEdit()
        self.targets.setPlaceholderText("One domain or URL per line\nexample.com\nhttps://app.example.com/")
        self.targets.setToolTip("Enter one domain or full URL per line. Radar checks ports 80 and 443 and discovers related subdomains using the enabled options.")
        self.targets.setMinimumHeight(100)
        target_layout.addWidget(self.targets)
        load = QPushButton("Load list…")
        load.setToolTip("Load a text file with one domain or URL per line.")
        load.clicked.connect(self.import_targets)
        target_layout.addWidget(load)
        grid.addWidget(target_group, 0, 0, Qt.AlignmentFlag.AlignTop)

        discovery_group = QGroupBox("Discovery")
        discovery_layout = QVBoxLayout(discovery_group)
        self.passive = self.option(discovery_layout, "Find public subdomains",
            "Find possible subdomains in public certificate and host records, and in links on the entered site's homepage. Radar then checks which names resolve and respond.",
            "Queries public data providers and makes DNS and web requests to the names they return. This can take longer; old records may lead to names that no longer exist.")
        self.passive.setChecked(True)
        self.active_dns = self.option(discovery_layout, "Check common subdomains",
            "Try common names such as www, app and admin from the editable DNS name list for each entered domain.",
            "Makes DNS queries for every name, then web requests to names that resolve. Larger lists take longer and may appear in DNS or site logs.")
        self.active_dns.setChecked(True)
        self.extra = self.option(discovery_layout, "Check other web ports",
            "Look for websites on the additional port numbers shown below. Ports 80 and 443 are always checked.",
            "Opens more connections and sends web requests to the selected ports. This may take longer and appear in firewall or server logs.")
        self.port_row = QWidget()
        port_layout = QVBoxLayout(self.port_row)
        port_layout.setContentsMargins(0, 2, 0, 0)
        port_layout.setSpacing(2)
        port_layout.addWidget(QLabel("Additional ports"))
        port_input_row = QHBoxLayout()
        port_input_row.setContentsMargins(0, 0, 0, 0)
        port_input_row.setSpacing(6)
        self.ports = QLineEdit(", ".join(map(str, WEB_PORTS[2:])))
        self.ports.setToolTip("Edit the additional ports here. Ports 80 and 443 are checked even when this option is off.")
        port_input_row.addWidget(self.ports, 1)
        port_input_row.addWidget(self.help_button(help_html(
            "Choose the extra port numbers to try when 'Check other web ports' is on. Ports 80 and 443 are always included.",
            "Each added port means more connection attempts for every discovered site, so the scan can take longer."), "Additional ports"))
        port_layout.addLayout(port_input_row)
        self.port_row.setVisible(False)
        self.extra.toggled.connect(self.port_row.setVisible)
        self.extra.toggled.connect(lambda checked: self.ports.setCursorPosition(0) if checked else None)
        discovery_layout.addWidget(self.port_row)
        self.advanced_discovery = QWidget()
        self.advanced_discovery.setObjectName("advancedPane")
        advanced_discovery_layout = QVBoxLayout(self.advanced_discovery)
        advanced_discovery_layout.setContentsMargins(0, 0, 0, 0)
        edit_words = QPushButton("Edit DNS names…")
        edit_words.setToolTip("Change the common names used for the DNS check.")
        edit_words.clicked.connect(self.edit_words)
        advanced_discovery_layout.addWidget(edit_words)
        self.recursive_dns = self.option(advanced_discovery_layout, "Check deeper subdomains",
            "After 'Check common subdomains' finds a name, try common names one level below it, such as api.dev.example.com. Checks at most 20 parent names and 50 labels under each.",
            "Can add up to 1,000 DNS candidates per entered domain, followed by web checks for names that resolve. This can substantially extend the scan.")
        self.tls_names = self.option(advanced_discovery_layout, "Read names from TLS certificates",
            "Read the public names listed in the entered site's HTTPS certificate and check any that belong to the same domain.",
            "Adds a certificate connection plus DNS and web checks for listed names. A certificate name alone does not prove a live site.")
        self.tls_names.setChecked(True)
        self.crawl = self.option(advanced_discovery_layout, "Check pages within each site",
            "Follow ordinary links on each responding site and read robots.txt and sitemap.xml to find more pages that may reveal PHP. Up to 12 pages are visited per web endpoint; forms are not submitted.",
            "Sends extra GET requests to the site and may take longer or appear in its logs. A poorly designed site could change state even on a GET request.")
        self.all_addresses = self.option(advanced_discovery_layout, "Check every IP address",
            "When a name has several IP addresses, check its website on each address separately. This can reveal different back-end servers.",
            "Repeats web checks for each address and can greatly increase scan time and traffic. Each back-end may show a different result.")
        advanced_discovery_layout.addStretch()
        grid.addWidget(discovery_group, 0, 1, Qt.AlignmentFlag.AlignTop)

        detection_group = QGroupBox("PHP detection")
        detection_group.setToolTip("Standard checks read existing responses. Reading public PHP diagnostic pages is on by default; the active POST check requires a separate opt-in.")
        detection_layout = QVBoxLayout(detection_group)
        self.patch_collection = self.option(detection_layout, "Read optional PHP diagnostic pages",
            "Read phpinfo.php and info.php if the site already exposes them. They may report the PHP version or a patch clue, but are usually absent and are not needed for standard detection.",
            "Adds up to two GET requests per checked web endpoint. It does not submit data or pressure PHP memory, but exposed diagnostic pages may contain sensitive configuration.")
        self.patch_collection.setChecked(True)
        self.active_check = self.option(detection_layout, "Active check if unclear",
            "When the PHP patch level is unclear or an older version is reported, Radar reads optional diagnostic pages, then sends a small session check and repeats it if PHP warnings appear. This can also uncover PHP that public pages do not identify. For WordPress, Radar may check wp-login.php when the front page gives no signal. Repeated pre-fix behavior means Vulnerable. Only sites already identified as PHP may receive up to three bounded memory checks if the small check is inconclusive. No executable code is sent and existing cookies are not reused.",
            "The small checks may show PHP warnings in the response. The later memory checks can exhaust a worker's memory, interrupt a request or briefly reduce site availability; the upload-progress method may create temporary session data. Radar stops on unusual or rejected responses. Hidden errors and a memory error alone cannot prove safety or vulnerability.", warning=True)
        self.advanced_detection = QWidget()
        self.advanced_detection.setObjectName("advancedPane")
        advanced_detection_layout = QVBoxLayout(self.advanced_detection)
        advanced_detection_layout.setContentsMargins(0, 0, 0, 0)
        self.verify_tls = self.option(advanced_detection_layout, "Verify TLS certificates",
            "Check that HTTPS certificates are trusted and match the website name. This is on by default.",
            "Turning it off lets Radar inspect sites with self-signed or invalid certificates, but the website's identity is no longer verified and results may be less trustworthy.")
        self.verify_tls.setChecked(True)
        settings = QFormLayout()
        self.workers = QSpinBox()
        self.workers.setRange(1, 32)
        self.workers.setValue(8)
        self.workers.setToolTip("Number of addresses checked at the same time.")
        settings.addRow(self.form_label("Concurrent checks", "Set how many website addresses Radar can check at once.",
                                       "A higher number can finish sooner but makes more simultaneous connections and may put more load on sites."), self.workers)
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(1, 60)
        self.timeout.setValue(7)
        self.timeout.setSuffix(" s")
        self.timeout.setToolTip("Seconds to wait for a response from one address.")
        settings.addRow(self.form_label("Timeout", "Set how long Radar waits for an individual network response.",
                                       "A shorter timeout speeds up unreachable sites but may miss slow ones. A longer timeout can make scans take longer."), self.timeout)
        self.interval = QDoubleSpinBox()
        self.interval.setRange(0.1, 10)
        self.interval.setValue(0.35)
        self.interval.setSingleStep(0.1)
        self.interval.setSuffix(" s")
        self.interval.setToolTip("Minimum time between requests to the same domain.")
        settings.addRow(self.form_label("Request interval", "Set the minimum pause between requests to the same host.",
                                       "A shorter pause finishes sooner but sends requests more frequently; a longer pause is gentler and slower."), self.interval)
        advanced_detection_layout.addLayout(settings)
        advanced_detection_layout.addStretch()
        grid.addWidget(detection_group, 0, 2, Qt.AlignmentFlag.AlignTop)
        for col in range(3):
            grid.setColumnStretch(col, 1)
        self.advanced_dialog = QDialog(self)
        self.advanced_dialog.setWindowTitle("More options")
        dialog_layout = QVBoxLayout(self.advanced_dialog)
        dialog_layout.setContentsMargins(18, 16, 18, 16)
        option_columns = QHBoxLayout()
        option_columns.setSpacing(12)
        discovery_extras = QGroupBox("Discovery extras")
        discovery_extras_layout = QVBoxLayout(discovery_extras)
        discovery_extras_layout.addWidget(self.advanced_discovery)
        option_columns.addWidget(discovery_extras, 1)
        scan_settings = QGroupBox("Scan behavior")
        scan_settings_layout = QVBoxLayout(scan_settings)
        scan_settings_layout.addWidget(self.advanced_detection)
        option_columns.addWidget(scan_settings, 1)
        dialog_layout.addLayout(option_columns, 1)
        done = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        done.rejected.connect(self.advanced_dialog.reject)
        dialog_layout.addWidget(done)
        self.advanced_dialog.resize(980, 480)
        splitter.addWidget(config)

        results = QWidget()
        result_layout = QVBoxLayout(results)
        result_layout.setContentsMargins(0, 0, 0, 0)
        toolbar = QHBoxLayout()
        self.start_btn = QPushButton("Scan")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self.start_scan)
        toolbar.addWidget(self.start_btn)
        self.pause_btn = QPushButton("Pause")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.pause_scan)
        toolbar.addWidget(self.pause_btn)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        toolbar.addWidget(self.stop_btn)
        toolbar.addStretch()
        self.summary = QLabel("PHP sites 0/0")
        self.summary.setObjectName("metric")
        self.summary.setToolTip("PHP sites / all reached websites. DNS candidates and unreachable addresses are not counted.")
        toolbar.addWidget(self.summary)
        self.show_other = QCheckBox("Show other sites")
        self.show_other.setEnabled(False)
        self.show_other.setToolTip("After a completed scan, show reached websites where PHP was not detected below the PHP results. An absent PHP indicator does not rule out PHP.")
        self.show_other.toggled.connect(lambda _: self.refresh_results(animate=False))
        toolbar.addWidget(self.show_other)
        result_layout.addLayout(toolbar)
        search_row = QHBoxLayout()
        self.search_label = QLabel("PHP sites found")
        search_row.addWidget(self.search_label)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search PHP sites…")
        self.search.textChanged.connect(self.filter_rows)
        search_row.addWidget(self.search, 1)
        result_layout.addLayout(search_row)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Address", "HTTP", "PHP", "Version", "Active check", "Result"])
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        samples = {
            1: ("HTTP", "503"),
            2: ("PHP", "Detected"),
            3: ("Version", "8.4.26-ubuntu1"),
            4: ("Active check", "Redirects to HTTPS", "Anomaly found", "Service issue"),
            5: ("Result", "Fixed version", "Unconfirmed", "Vulnerable"),
        }
        self.table.ensurePolished()
        item_metrics = self.table.fontMetrics()
        header_metrics = self.table.horizontalHeader().fontMetrics()
        for column, texts in samples.items():
            width = max(max(item_metrics.horizontalAdvance(value) for value in texts),
                        header_metrics.horizontalAdvance(texts[0])) + 24
            self.table.setColumnWidth(column, width)
        for column in range(self.table.columnCount()):
            alignment = Qt.AlignmentFlag.AlignVCenter | (Qt.AlignmentFlag.AlignLeft if column == 0 else Qt.AlignmentFlag.AlignHCenter)
            self.table.horizontalHeaderItem(column).setTextAlignment(alignment)
        self.table.setItemDelegate(ResultFadeDelegate(self))
        self.table.cellClicked.connect(self.toggle_result_group)
        self.table.cellDoubleClicked.connect(self.show_details)
        result_layout.addWidget(self.table, 1)
        status_row = QHBoxLayout()
        self.current_status = QLabel("Ready to scan")
        self.current_status.setObjectName("currentStatus")
        self.current_status.setToolTip("Shows only the current task. Open the journal for full activity details.")
        status_row.addWidget(self.current_status, 1)
        self.drawer_btn = QPushButton("Journal  ›")
        self.drawer_btn.setObjectName("drawerButton")
        self.drawer_btn.setCheckable(True)
        self.drawer_btn.setToolTip("Show or hide the detailed scan activity.")
        self.drawer_btn.toggled.connect(self.toggle_drawer)
        status_row.addWidget(self.drawer_btn)
        result_layout.addLayout(status_row)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        result_layout.addWidget(self.progress)
        splitter.addWidget(results)
        splitter.setSizes([215, 525])
        body = QHBoxLayout()
        body.setSpacing(8)
        body.addWidget(splitter, 1)
        self.drawer = QWidget()
        self.drawer.setFixedWidth(0)
        drawer_layout = QVBoxLayout(self.drawer)
        drawer_layout.setContentsMargins(12, 10, 4, 0)
        drawer_layout.addWidget(QLabel("Activity journal"))
        self.activity = QPlainTextEdit()
        self.activity.setReadOnly(True)
        self.activity.setMaximumBlockCount(1500)
        drawer_layout.addWidget(self.activity)
        body.addWidget(self.drawer)
        root.addLayout(body, 1)
        self.animation = QVariantAnimation(self)
        self.animation.valueChanged.connect(lambda width: self.drawer.setFixedWidth(int(width)))
        self.animation.setDuration(220)
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.statusBar().hide()

    def help_button(self, explanation, title, warning=False):
        button = QToolButton()
        button.setText("?")
        button.setObjectName("helpButtonWarning" if warning else "helpButton")
        button.setFixedSize(22, 22)
        button.setToolTip(explanation)
        button.setAccessibleName(f"Help: {title}")
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.clicked.connect(lambda: QToolTip.showText(
            button.mapToGlobal(QPoint(0, button.height() + 4)), explanation, button))
        self.help_buttons[title] = button
        return button

    def form_label(self, title, description, impact):
        explanation = help_html(description, impact)
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 4, 0)
        row_layout.setSpacing(6)
        label = QLabel(title)
        label.setToolTip(explanation)
        row_layout.addWidget(label)
        row_layout.addWidget(self.help_button(explanation, title))
        return row

    def option(self, layout, title, description, impact, warning=False):
        explanation = help_html(description, impact)
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(4)
        box = QCheckBox(title)
        box.setToolTip(explanation)
        row_layout.addWidget(box, 1)
        row_layout.addWidget(self.help_button(explanation, title, warning))
        layout.addWidget(row)
        return box

    def open_advanced(self):
        available = QApplication.primaryScreen().availableGeometry()
        self.advanced_dialog.resize(min(980, available.width() - 36),
                                    min(480, available.height() - 48))
        self.advanced_dialog.exec()

    def toggle_drawer(self, opened):
        self.animation.stop()
        self.animation.setStartValue(self.drawer.width())
        width = self.journal_width() if opened else 0
        self.animation.setEndValue(width)
        self.drawer_btn.setText("Hide journal  ‹" if opened else "Journal  ›")
        if self.isVisible():
            self.animation.start()
        else:
            self.drawer.setFixedWidth(width)

    def journal_width(self):
        return min(600, max(360, int(self.width() * 0.45)))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, "drawer") and hasattr(self, "drawer_btn") and self.drawer_btn.isChecked():
            if hasattr(self, "animation"):
                self.animation.stop()
            self.drawer.setFixedWidth(self.journal_width())

    def import_targets(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load domains", "", "Text files (*.txt);;All files (*)")
        if path:
            try:
                self.targets.setPlainText(Path(path).read_text(encoding="utf-8-sig"))
            except OSError as exc:
                QMessageBox.warning(self, "Could not load file", str(exc))

    def edit_words(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("DNS names to check")
        dialog.resize(480, 520)
        layout = QVBoxLayout(dialog)
        layout.addWidget(muted("One name per line, such as www, admin or api.dev. Each name is checked for every entered domain."))
        editor = QPlainTextEdit("\n".join(self.words))
        layout.addWidget(editor)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec():
            words = list(dict.fromkeys(editor.toPlainText().lower().split()))
            if not words or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", w) or ".." in w for w in words):
                QMessageBox.warning(self, "Invalid names", "Enter valid DNS names, one per line.")
                return
            self.words = words
            self.active_dns.setText(f"Check {len(words)} subdomains")

    def options(self):
        ports = []
        if self.extra.isChecked():
            ports = list(dict.fromkeys(int(p) for p in re.split(r"[,\s]+", self.ports.text().strip()) if p))
            if not ports or any(not 1 <= p <= 65535 for p in ports):
                raise ValueError("Ports must be between 1 and 65535.")
        return ScanOptions(targets=parse_targets(self.targets.toPlainText()), passive_dns=self.passive.isChecked(),
                           active_dns=self.active_dns.isChecked(), extra_ports=self.extra.isChecked(), ports=ports,
                           words=self.words.copy(), active_check=self.active_check.isChecked(),
                           collect_patch_evidence=self.patch_collection.isChecked(),
                           concurrency=self.workers.value(), timeout=self.timeout.value(), interval=self.interval.value(),
                           verify_tls=self.verify_tls.isChecked(), recursive_dns=self.recursive_dns.isChecked(),
                           tls_names=self.tls_names.isChecked(), all_addresses=self.all_addresses.isChecked(),
                           crawl=self.crawl.isChecked())

    def start_scan(self):
        if self.thread and self.thread.isRunning():
            return
        try:
            options = self.options()
        except ValueError as exc:
            QMessageBox.warning(self, "Check the addresses", str(exc))
            return
        self.stop_result_fades()
        self.assets.clear()
        self.rows.clear()
        self.row_members.clear()
        self.row_search_members.clear()
        self.row_group_keys.clear()
        self.expandable_rows.clear()
        self.expanded_pairs.clear()
        self.root_result_count = 0
        self.other_rows.clear()
        self.other_search_members.clear()
        self.other_expandable_rows.clear()
        self.other_expanded_pairs.clear()
        self.other_header_row = None
        self.other_result_count = 0
        self.show_other.setChecked(False)
        self.show_other.setEnabled(False)
        self.table.setRowCount(0)
        self.activity.clear()
        self.summary.setText("PHP sites 0/0")
        self.run_record = {}
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.pause_btn.setText("Pause")
        self.stop_btn.setEnabled(True)
        self.current_status.setText("Preparing scan…")
        self.thread = ScanThread(options, self)
        self.thread.event.connect(self.on_event)
        self.thread.finished.connect(self.thread_done)
        self.thread.start()

    def pause_scan(self):
        if not self.thread:
            return
        if self.thread.control.paused.is_set():
            self.thread.control.paused.clear()
            self.pause_btn.setText("Pause")
            self.current_status.setText("Resuming scan…")
        else:
            self.thread.control.paused.set()
            self.pause_btn.setText("Resume")
            self.current_status.setText("Paused")

    def stop_scan(self):
        if self.thread:
            self.thread.control.stopped.set()
            self.thread.control.paused.clear()
            self.pause_btn.setEnabled(False)
            self.stop_btn.setEnabled(False)
            self.current_status.setText("Stopping scan…")

    def thread_done(self):
        self.start_btn.setEnabled(True)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        old_thread = self.thread
        self.thread = None
        if old_thread:
            old_thread.deleteLater()
        if self.close_requested:
            self.close()

    def persist(self, action, *args):
        if self.storage_failed:
            return
        try:
            action(*args)
        except Exception as exc:
            self.storage_failed = True
            self.activity.appendPlainText(f"Session storage failed: {exc}. Export the current report to retain results.")
            self.current_status.setText("Could not save session · export the results")

    def on_event(self, event):
        kind = event["type"]
        if kind == "started":
            self.run_record = dict(event)
            self.run_record["status"] = "RUNNING"
            self.current_status.setText("Preparing scan…")
            self.persist(self.store.save_run, self.run_record)
        elif kind == "asset":
            asset = event["asset"]
            self.update_asset(asset)
            self.persist(self.store.save_asset, self.run_record["id"], asset)
        elif kind == "stage":
            self.activity.appendPlainText(event["stage"])
            self.progress.setRange(0, event["total"])
            self.progress.setValue(0)
            self.current_status.setText({"DNS / certificate discovery": "Finding domains and addresses…",
                                         "HTTP / PHP detection": "Checking sites for PHP…"}.get(event["stage"], event["stage"]))
        elif kind == "progress":
            self.progress.setRange(0, event["total"])
            self.progress.setValue(event["completed"])
            self.current_status.setText(f"Checking sites…  {event['completed']}/{event['total']}")
            self.activity.appendPlainText(f"[{event['completed']}/{event['total']}] {event['current']}")
        elif kind == "host":
            label = "Wildcard candidate" if event.get("wildcard_ambiguous") else "DNS candidate"
            self.activity.appendPlainText(f"{label}: {event['host']} → {', '.join(event['ips']) or 'unresolved'}")
            settings = dict(self.run_record["options"])
            settings["targets"] = [Target(**target) for target in settings["targets"]]
            settings.pop("subfinder_path", None)  # Older saved runs may have used the removed option.
            options = ScanOptions(**settings)
            if options.all_addresses:
                return
            target = Target(event["host"])
            for url in endpoints(target, options):
                if url not in self.assets:
                    self.on_event({"type": "asset", "asset": pending_asset(url, target, event["ips"], event["source"])})
        elif kind == "dns_tick":
            self.current_status.setText("Checking DNS: " + event["host"])
        elif kind == "log":
            self.activity.appendPlainText(event["message"])
        elif kind == "finished":
            self.run_record.update(event)
            for url, asset in list(self.assets.items()):
                if asset["assessment"] == "PENDING":
                    asset = dict(asset, assessment="NOT_TESTED", php="NOT_ESTABLISHED", error="Scan ended before this endpoint was checked.")
                    self.update_asset(asset)
                    self.persist(self.store.save_asset, self.run_record["id"], asset)
            if self.run_record.get("id"):
                self.persist(self.store.save_run, self.run_record)
            self.progress.setRange(0, 100)
            self.progress.setValue(100 if event["status"] == "COMPLETED" else 0)
            self.activity.appendPlainText(event["status"] + (": " + event["error"] if event.get("error") else ""))
            if event.get("coverage"):
                self.activity.appendPlainText("Coverage: " + json.dumps(event["coverage"], ensure_ascii=False))
            self.current_status.setText({"COMPLETED": "Done", "STOPPED": "Stopped", "FAILED": "Failed"}.get(event["status"], event["status"]))
            self.show_other.setEnabled(event["status"] == "COMPLETED")

    def update_asset(self, asset, refresh=True):
        url = asset.get("id", asset["url"])
        was_php = self.assets.get(url, {}).get("php") in ("DETECTED", "LIKELY")
        self.assets[url] = asset
        if refresh and (was_php or asset["php"] in ("DETECTED", "LIKELY")):
            self.refresh_results()
        elif refresh:
            self.update_result_count()
        self.export_btn.setEnabled(bool(self.assets))

    def stop_result_fades(self):
        for animation in self.row_fades.values():
            animation.stop()
            animation.deleteLater()
        self.row_fades.clear()
        self.row_opacity.clear()

    def start_result_fade(self, key):
        animation = QVariantAnimation(self)
        animation.setStartValue(0.18)
        animation.setEndValue(1.0)
        animation.setDuration(420)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.row_opacity[key] = 0.18

        def update(value):
            self.row_opacity[key] = float(value)
            self.table.viewport().update()

        def finished():
            self.row_fades.pop(key, None)
            self.row_opacity.pop(key, None)
            self.table.viewport().update()
            animation.deleteLater()

        animation.valueChanged.connect(update)
        animation.finished.connect(finished)
        self.row_fades[key] = animation
        animation.start()

    def refresh_results(self, animate=True):
        previous = {}
        for representative, row in self.rows.items():
            item = self.table.item(row, 5)
            if item:
                previous.update({member: item.text() for member in self.row_members[representative]})
        layout, self.root_result_count = result_layout(self.assets, self.expanded_pairs)
        other_layout, self.other_result_count = result_layout(self.assets, self.other_expanded_pairs,
                                                              php_only=False)
        if not self.show_other.isChecked():
            other_layout = []
        other_start = len(layout) + (1 if other_layout else 0)
        visible_keys = {key for key, _, _, _, _ in layout}
        for key in set(self.row_fades) - visible_keys:
            animation = self.row_fades.pop(key)
            animation.stop()
            animation.deleteLater()
            self.row_opacity.pop(key, None)
        scroll = self.table.verticalScrollBar().value()
        self.table.setUpdatesEnabled(False)
        fade_keys = []
        try:
            self.table.setRowCount(other_start + len(other_layout))
            self.rows.clear()
            self.row_members.clear()
            self.row_search_members.clear()
            self.expandable_rows.clear()
            self.other_rows.clear()
            self.other_search_members.clear()
            self.other_expandable_rows.clear()
            self.other_header_row = len(layout) if other_layout else None
            self.row_group_keys = ([group_key for group_key, _, _, _, _ in layout]
                                   + ([None] if other_layout else [])
                                   + [("other", group_key) for group_key, _, _, _, _ in other_layout])
            for row, (group_key, members, pair_id, child, search_members) in enumerate(layout):
                representative = min(members, key=lambda key: result_preference(self.assets[key]))
                self.rows[representative] = row
                self.row_members[representative] = members
                self.row_search_members[representative] = search_members
                if pair_id:
                    self.expandable_rows[row] = pair_id
                prefix = ("    ↳ " if child else "▾ " if pair_id and pair_id in self.expanded_pairs else
                          "▸ " if pair_id else "")
                self.render_result_row(self.assets[representative], row, members, prefix,
                                       expandable=bool(pair_id))
                verdict = self.table.item(row, 5).text()
                if (animate and self.isVisible() and group_key not in self.row_fades and
                        (not any(member in previous for member in members) or
                         any(previous[member] != verdict for member in members if member in previous))):
                    self.row_opacity[group_key] = 0.18
                    fade_keys.append(group_key)
            if other_layout:
                self.render_other_header(self.other_header_row)
            for offset, (group_key, members, pair_id, child, search_members) in enumerate(other_layout):
                row = other_start + offset
                representative = min(members, key=lambda key: result_preference(self.assets[key]))
                self.other_rows[representative] = row
                self.other_search_members[representative] = search_members
                if pair_id:
                    self.other_expandable_rows[row] = pair_id
                prefix = ("    ↳ " if child else "▾ " if pair_id and pair_id in self.other_expanded_pairs else
                          "▸ " if pair_id else "")
                self.render_other_row(self.assets[representative], row, members, prefix, bool(pair_id))
        finally:
            self.table.setUpdatesEnabled(True)
        self.table.verticalScrollBar().setValue(scroll)
        self.search_label.setText("All discovered sites" if self.show_other.isChecked() else "PHP sites found")
        self.search.setPlaceholderText("Search all sites…" if self.show_other.isChecked() else "Search PHP sites…")
        self.update_result_count()
        self.filter_rows()
        for key in fade_keys:
            self.start_result_fade(key)

    def toggle_result_group(self, row, column):
        if column != 0:
            return
        if row in self.expandable_rows:
            pair_id = self.expandable_rows[row]
            expanded = self.expanded_pairs
        elif row in self.other_expandable_rows:
            pair_id = self.other_expandable_rows[row]
            expanded = self.other_expanded_pairs
        else:
            return
        if pair_id in expanded:
            expanded.remove(pair_id)
        else:
            expanded.add(pair_id)
        self.refresh_results(animate=False)

    def render_other_header(self, row):
        for column in range(self.table.columnCount()):
            item = QTableWidgetItem("Other discovered sites · PHP not detected" if column == 0 else "")
            item.setBackground(QColor("#eef4fb"))
            item.setForeground(QColor("#526477"))
            font = item.font()
            font.setBold(True)
            item.setFont(font)
            self.table.setItem(row, column, item)

    def render_other_row(self, asset, row, members, address_prefix="", expandable=False):
        display_url = result_address(asset)
        tooltip = ("Radar reached this website but found no public PHP indicators. "
                   "This does not rule out PHP.")
        if len(members) > 1:
            tooltip += "\nAlso checked: " + ", ".join(self.assets[key]["url"] for key in members)
        if expandable:
            tooltip += "\nClick to show or hide the HTTPS address."
        values = [address_prefix + display_url, str(asset["http_status"]), "", "", "", ""]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter |
                                  (Qt.AlignmentFlag.AlignLeft if column == 0 else Qt.AlignmentFlag.AlignHCenter))
            item.setToolTip(tooltip if column == 0 else value)
            item.setForeground(QColor("#687785"))
            self.table.setItem(row, column, item)

    def render_result_row(self, asset, row, members, address_prefix="", expandable=False):
        url = asset.get("id", asset["url"])
        active_asset = preferred_active_asset(self.assets, members, asset)
        active_label, active_tooltip = active_display(active_asset.get("active", {}), active_asset)
        display_url = result_address(asset)
        if (active_label == "Redirects to HTTPS" and
                urlsplit(display_url).scheme == "https"):
            checked_at = active_asset.get("active", {}).get("checked_at")
            active_label = "Not retested" if checked_at else "Not checked"
            active_tooltip = (f"The HTTP address led to this HTTPS site. Active requests ran at {checked_at}." if checked_at else
                              "The HTTP address led to this HTTPS site. No active POST was sent to it.")
        php_label = {"DETECTED": "Detected", "LIKELY": "Likely",
                     "NOT_ESTABLISHED": "Unclear", "PENDING": "Pending"}.get(asset["php"], asset["php"])
        verdict = asset.get("verdict") or "Unconfirmed"
        values = [address_prefix + display_url, str(asset.get("http_status", "—")), php_label,
                  asset.get("version") or "—", active_label, verdict]
        verdict_tooltip = {"Fixed version": "The site reports a PHP version with the upstream fix. Verify the version actually installed.",
                           "At risk": "The site reports a PHP version from before the upstream fix. Check for vendor backports.",
                           "Vulnerable": "Two small active requests found PHP session behavior from before the security fix. This identifies an unpatched code path, not code execution.",
                           "Unconfirmed": "PHP was found, but the public evidence cannot establish its patch level. Check server or hosting inventory."}.get(verdict, "No assessment available.")
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if col == 0:
                item.setData(Qt.ItemDataRole.UserRole, url)
            item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | (Qt.AlignmentFlag.AlignLeft if col == 0 else Qt.AlignmentFlag.AlignHCenter))
            address_tip = f"Reached from {asset['url']}" if display_url != asset["url"] else display_url
            if col == 0 and len(members) > 1:
                address_tip += "\nAlso checked: " + ", ".join(self.assets[key]["url"] for key in members if key != url)
            if col == 0 and expandable:
                address_tip += "\nClick to show or hide the HTTPS address."
            item.setToolTip(asset.get("error") or (verdict_tooltip if col == 5 else active_tooltip if col == 4 else address_tip if col == 0 else value))
            if col == 5:
                foreground, background = {
                    "Vulnerable": ("#a81f39", "#fde8eb"),
                    "At risk": ("#a44729", "#fff0e7"),
                    "Fixed version": ("#176b52", "#e1f5ec"),
                    "Unconfirmed": ("#8b611d", "#fff2d5"),
                }.get(verdict, ("#526477", "#edf2f7"))
                item.setForeground(QColor(foreground))
                item.setBackground(QColor(background))
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self.table.setItem(row, col, item)

    def update_result_count(self):
        _, self.other_result_count = result_layout(self.assets, set(), php_only=False)
        self.summary.setText(f"PHP sites {self.root_result_count}/{self.root_result_count + self.other_result_count}")

    def filter_rows(self):
        needle = self.search.text().lower()
        for url, row in self.rows.items():
            self.table.setRowHidden(row, not any(
                needle in json.dumps(self.assets[key]).lower() for key in self.row_search_members[url]))
        for url, row in self.other_rows.items():
            self.table.setRowHidden(row, not any(
                needle in json.dumps(self.assets[key]).lower() for key in self.other_search_members[url]))
        if self.other_header_row is not None:
            self.table.setRowHidden(self.other_header_row,
                                    not any(not self.table.isRowHidden(row) for row in self.other_rows.values()))

    def show_details(self, row, _column):
        if row not in self.rows.values():
            return
        url = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        asset = self.assets[url]
        active_asset = preferred_active_asset(self.assets, self.row_members.get(url, [url]), asset)
        dialog = QDialog(self)
        dialog.setWindowTitle("Site details")
        dialog.resize(760, 550)
        layout = QVBoxLayout(dialog)
        summary = QTextBrowser()
        summary.setOpenExternalLinks(False)
        version = escape(asset.get("version") or "Not established")
        verdict = escape(asset.get("verdict", "Unconfirmed"))
        reason = escape(asset.get("verdict_reason") or {
            "Fixed version": "The site reports a PHP version with the upstream fix. Verify the installed version.",
            "At risk": "The site reports a PHP version from before the upstream fix. A vendor backport may apply.",
            "Vulnerable": "Repeated active requests found an unpatched PHP session code path. No code execution or data extraction was attempted.",
            "Unconfirmed": "Public evidence is insufficient for a confident assessment.",
        }.get(asset.get("verdict"), "Insufficient evidence for a precise assessment."))
        clues = []
        for entry in asset.get("evidence", [])[:12]:
            clues.append(f"<li>{escape(str(entry.get('value') or entry.get('source') or entry.get('type') or 'Signal'))}</li>")
        if not clues:
            clues.append("<li>No public PHP indicators were found.</li>")
        active = active_asset.get("active", {})
        active_text = escape(active_display(active, active_asset)[1])
        method_names = {"part_headers": "Multipart part headers", "nested_empty_files": "Nested empty uploads",
                        "session_upload_progress": "Session upload progress"}
        outcome_names = {"OOM_TEXT_OBSERVED": "memory exhaustion observed", "HTTP_RESPONSE_RECEIVED": "response received",
                         "REJECTED_OR_THROTTLED": "blocked or throttled", "SERVER_ERROR_UNSPECIFIC": "server error",
                         "REQUEST_ERROR_UNSPECIFIC": "request failed", "SESSION_COOKIE_LENGTH_ANOMALY": "cookie-size anomaly"}
        active_methods = "".join(
            f"<li>{escape(method_names.get(entry.get('method'), 'Multipart check'))}: "
            f"{escape(outcome_names.get(entry.get('observation'), 'inconclusive'))}</li>"
            for entry in active.get("evidence", []) if entry.get("type") == "bounded_oom_probe")
        aliases = [self.assets[key]["url"] for key in self.row_members.get(url, []) if key != url]
        other_pages = sorted({self.assets[key].get("final_url") for key in self.row_members.get(url, [])
                              if self.assets[key].get("final_url") and
                              self.assets[key]["final_url"] != result_address(asset)})
        summary.setHtml(
            f"<h2>{escape(result_address(asset))}</h2>"
            + (f"<p><b>Reached from:</b> {escape(asset['url'])}</p>" if result_address(asset) != asset['url'] else "") +
            (f"<p><b>Also checked at:</b> {', '.join(escape(other) for other in aliases)}</p>" if aliases else "") +
            (f"<p><b>Reached pages:</b> {', '.join(escape(page) for page in other_pages)}</p>" if other_pages else "") +
            f"<p><b>Assessment:</b> {verdict}<br><b>Reported PHP version:</b> {version}</p>"
            f"<p>{reason}</p>"
            f"<h3>What we found</h3><ul>{''.join(clues)}</ul>"
            f"<h3>Active check</h3><p>{active_text}</p>"
            + (f"<p><b>Active evidence from:</b> {escape(active_asset.get('final_url') or active_asset['url'])}</p>"
               if active_asset is not asset else "")
            + (f"<ul>{active_methods}</ul>" if active_methods else "") +
            "<p><small>Public indicators cannot verify the installed package or every PHP process.</small></p>")
        layout.addWidget(summary, 1)
        technical_btn = QPushButton("Show technical details")
        technical_btn.setCheckable(True)
        group_assets = [self.assets[key] for key in self.row_members.get(url, [url])]
        technical_assets = ({"displayed_site": asset, "checked_addresses": group_assets}
                            if len(group_assets) > 1 else asset)
        technical = QPlainTextEdit(json.dumps(technical_assets, indent=2, ensure_ascii=False))
        technical.setReadOnly(True)
        technical.setVisible(False)
        technical_btn.toggled.connect(technical.setVisible)
        technical_btn.toggled.connect(lambda shown: technical_btn.setText("Hide technical details" if shown else "Show technical details"))
        layout.addWidget(technical_btn)
        layout.addWidget(technical, 1)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.reject)
        layout.addWidget(close)
        dialog.exec()

    def export(self):
        path, selected = QFileDialog.getSaveFileName(self, "Export report", "php2shell-report.json", "JSON report (*.json);;CSV report (*.csv)")
        if path:
            if not Path(path).suffix:
                path += ".csv" if selected.startswith("CSV") else ".json"
            try:
                export_report(path, self.run_record, list(self.assets.values()))
                self.current_status.setText("Report saved")
            except OSError as exc:
                QMessageBox.warning(self, "Export failed", str(exc))

    def open_history(self):
        if self.thread and self.thread.isRunning():
            QMessageBox.information(self, "Scan in progress", "Stop the current scan before opening another session.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Saved sessions")
        dialog.resize(700, 380)
        layout = QVBoxLayout(dialog)
        listing = QListWidget()
        try:
            runs = self.store.runs()
        except Exception as exc:
            QMessageBox.warning(self, "History unavailable", str(exc))
            return
        for run in runs:
            listing.addItem(f"{run.get('started_at', '')}   {run.get('status', '')}   {run['id'][:8]}")
        layout.addWidget(listing)
        layout.addWidget(muted("If an older session is marked RUNNING, the app may have closed before that scan finished."))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Open | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        listing.itemDoubleClicked.connect(lambda _: dialog.accept())
        if dialog.exec() and listing.currentRow() >= 0:
            run = runs[listing.currentRow()]
            self.restore_session(run)

    def restore_session(self, run):
        self.run_record = run
        self.stop_result_fades()
        self.show_other.setChecked(False)
        self.show_other.setEnabled(False)
        self.assets.clear()
        self.rows.clear()
        self.row_members.clear()
        self.row_search_members.clear()
        self.row_group_keys.clear()
        self.expandable_rows.clear()
        self.expanded_pairs.clear()
        self.root_result_count = 0
        self.other_rows.clear()
        self.other_search_members.clear()
        self.other_expandable_rows.clear()
        self.other_expanded_pairs.clear()
        self.other_header_row = None
        self.other_result_count = 0
        self.table.setRowCount(0)
        for asset in self.store.assets(run["id"]):
            old_label = asset.get("verdict", "Unconfirmed")
            if old_label == "Vulnerable" and (asset.get("active") or {}).get("status") != "UNPATCHED_SESSION_PATH":
                old_label = "At risk"  # Previous releases used this label for version-only findings.
            asset["verdict"] = {"Fixed": "Fixed version",
                                "Needs verification": "Unconfirmed"}.get(old_label, old_label)
            self.update_asset(asset, refresh=False)
        self.refresh_results(animate=False)
        settings = run.get("options", {})
        targets = [Target(**target) for target in settings.get("targets", [])]
        self.targets.setPlainText("\n".join(t.url or t.host for t in targets))
        for key, widget in (("passive_dns", self.passive), ("active_dns", self.active_dns), ("extra_ports", self.extra), ("collect_patch_evidence", self.patch_collection), ("recursive_dns", self.recursive_dns), ("tls_names", self.tls_names), ("all_addresses", self.all_addresses), ("crawl", self.crawl)):
            widget.setChecked(settings.get(key, False))
        # A restored session must not silently re-send POST probes.
        self.active_check.setChecked(False)
        self.verify_tls.setChecked(settings.get("verify_tls", True))
        self.workers.setValue(settings.get("concurrency", 8))
        self.timeout.setValue(settings.get("timeout", 7))
        self.interval.setValue(settings.get("interval", 0.35))
        self.words = settings.get("words", self.words)
        self.active_dns.setText(f"Check {len(self.words)} subdomains")
        self.ports.setText(", ".join(map(str, settings.get("ports") or WEB_PORTS[2:])))
        self.current_status.setText("Previous session loaded")
        self.export_btn.setEnabled(bool(self.assets))
        self.show_other.setEnabled(run.get("status") == "COMPLETED")

    def closeEvent(self, event):
        if self.thread and self.thread.isRunning():
            self.close_requested = True
            self.stop_scan()
            self.current_status.setText("Stopping scan and closing…")
            event.ignore()
            return
        self.animation.stop()
        self.stop_result_fades()
        self.store.close()
        event.accept()
        # A one-file bundle has a parent and a GUI child. Do not leave the
        # child's Qt event loop alive if another hidden top-level widget exists.
        QApplication.instance().quit()


def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(files("hunter").joinpath("data/app-icon.png"))))
    app.setOrganizationName("PHP2ShellHunter")
    app.setApplicationName("PHP2Shell Radar")
    app.setApplicationDisplayName("PHP2Shell Radar")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    window = MainWindow()
    available = app.primaryScreen().availableGeometry()
    if available.width() < 1280 or available.height() < 820:
        window.showMaximized()
    else:
        window.resize(min(1360, available.width() - 40), min(840, available.height() - 40))
        window.move(available.center() - window.rect().center())
        window.show()
    sys.exit(app.exec())
