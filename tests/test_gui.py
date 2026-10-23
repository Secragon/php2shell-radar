import asyncio
import csv
import json
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path
import tempfile
import time
import unittest
from threading import Event
from unittest.mock import patch

from PySide6.QtCore import QCoreApplication, QEvent, QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QScrollArea, QToolTip, QWidget
from PySide6.QtGui import QFontDatabase

from hunter.gui import MainWindow, STYLE, active_display, existing_file
from hunter.detection import fingerprint
from hunter.models import CVES, endpoints
from hunter.storage import Store
from hunter.site_identity import describe_site
from hunter.network import Response


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        if not QFontDatabase.families() and Path("C:/Windows/Fonts/segoeui.ttf").exists():
            QFontDatabase.addApplicationFont("C:/Windows/Fonts/segoeui.ttf")
        cls.app.setStyle("Fusion")
        cls.app.setStyleSheet(STYLE)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.window = MainWindow(str(Path(self.directory.name) / "sessions.sqlite3"))

    def tearDown(self):
        self.window.animation.stop()
        self.window.close()
        self.window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.app.processEvents()
        self.directory.cleanup()

    @classmethod
    def tearDownClass(cls):
        cls.app.closeAllWindows()
        cls.app.quit()

    def test_default_options_and_toggles(self):
        self.assertEqual(self.window.windowTitle(), "PHP2Shell Radar")
        labels = [label.text() for label in self.window.findChildren(QLabel)]
        self.assertIn("PHP2Shell Radar", labels)
        self.assertNotIn("SECRAGON  /  PHP SECURITY", labels)
        self.assertNotIn("Passive detection is on", labels)
        self.assertFalse(self.window.windowIcon().isNull())
        self.window.targets.setPlainText("example.test")
        options = self.window.options()
        self.assertFalse(options.active_check)
        self.assertTrue(options.collect_patch_evidence)
        self.assertTrue(self.window.active_check.isEnabled())
        self.window.patch_collection.setChecked(False)
        self.assertFalse(self.window.options().collect_patch_evidence)
        self.assertFalse(self.window.options().active_check)
        self.window.active_check.setChecked(True)
        self.assertTrue(self.window.options().active_check)
        self.window.active_check.setChecked(False)
        self.assertTrue(options.active_dns)
        self.assertTrue(options.passive_dns)
        self.assertFalse(options.extra_ports)
        self.assertFalse(options.crawl)
        self.assertTrue(options.tls_names)
        self.assertFalse(options.all_addresses)
        self.assertFalse(options.recursive_dns)
        self.assertEqual(len(endpoints(options.targets[0], options)), 2)
        self.assertFalse(self.window.advanced_btn.isCheckable())
        self.assertFalse(self.window.drawer_btn.isChecked())
        self.assertEqual(self.window.drawer.maximumWidth(), 0)
        self.assertEqual(len(options.words), 100)
        self.window.extra.setChecked(True)
        self.assertFalse(self.window.port_row.isHidden())
        self.assertTrue(self.window.ports.isEnabled())
        self.assertEqual(len(self.window.options().ports), 8)
        self.assertFalse(hasattr(self.window, "subfinder"))
        self.assertNotIn("subfinder_path", options.to_dict())

    def test_scan_buttons_show_running_paused_stopping_and_idle_states(self):
        class FakeSignal:
            def connect(self, callback):
                pass

        class FakeThread:
            def __init__(self, options, parent):
                self.running = True
                self.control = type("Control", (), {"paused": Event(), "stopped": Event()})()
                self.event = FakeSignal()
                self.finished = FakeSignal()

            def start(self):
                pass

            def isRunning(self):
                return self.running

            def deleteLater(self):
                pass

        self.window.targets.setPlainText("example.test")
        self.assertEqual(self.window.start_btn.text(), "Scan")
        self.assertFalse(self.window.pause_btn.isEnabled())
        self.assertFalse(self.window.stop_btn.isEnabled())
        with patch("hunter.gui.ScanThread", FakeThread):
            self.window.start_btn.click()
        self.assertEqual(self.window.start_btn.text(), "Scanning…")
        self.assertFalse(self.window.start_btn.isEnabled())
        self.assertTrue(self.window.pause_btn.isEnabled())
        self.assertTrue(self.window.stop_btn.isEnabled())

        self.window.pause_btn.click()
        self.assertEqual(self.window.start_btn.text(), "Paused")
        self.assertEqual(self.window.pause_btn.text(), "Resume")
        self.assertTrue(self.window.pause_btn.isChecked())
        self.assertTrue(self.window.thread.control.paused.is_set())

        self.window.pause_btn.click()
        self.assertEqual(self.window.start_btn.text(), "Scanning…")
        self.assertEqual(self.window.pause_btn.text(), "Pause")
        self.assertFalse(self.window.pause_btn.isChecked())
        self.assertFalse(self.window.thread.control.paused.is_set())

        self.window.stop_btn.click()
        self.assertEqual(self.window.start_btn.text(), "Stopping…")
        self.assertEqual(self.window.stop_btn.text(), "Stopping…")
        self.assertFalse(self.window.pause_btn.isEnabled())
        self.assertFalse(self.window.stop_btn.isEnabled())
        self.assertTrue(self.window.thread.control.stopped.is_set())

        self.window.thread.running = False
        self.window.thread_done()
        self.assertEqual(self.window.start_btn.text(), "Scan")
        self.assertEqual(self.window.pause_btn.text(), "Pause")
        self.assertEqual(self.window.stop_btn.text(), "Stop")
        self.assertTrue(self.window.start_btn.isEnabled())

    def test_previous_app_name_keeps_saved_sessions(self):
        app_data = Path(self.directory.name) / "PHP2ShellHunter"
        legacy_path = app_data / "PHP2Shell Hunter" / "sessions.sqlite3"
        old_store = Store(str(legacy_path))
        old_store.save_run({"id": "saved-before-rename", "status": "COMPLETED"})
        old_store.close()
        with patch("hunter.gui.QStandardPaths.writableLocation", return_value=str(app_data / "PHP2Shell Radar")):
            reopened = MainWindow()
        try:
            self.assertEqual(reopened.store.runs()[0]["id"], "saved-before-rename")
        finally:
            reopened.animation.stop()
            reopened.close()
            reopened.deleteLater()

    def test_inaccessible_old_session_does_not_block_startup(self):
        with patch.object(Path, "is_file", side_effect=PermissionError("blocked")):
            self.assertFalse(existing_file(Path("unreadable.sqlite3")))
        app_data = Path(self.directory.name) / "PHP2ShellHunter" / "PHP2Shell Radar"
        with patch("hunter.gui.QStandardPaths.writableLocation", return_value=str(app_data)), \
             patch("hunter.gui.existing_file", return_value=False):
            reopened = MainWindow()
        try:
            self.assertEqual(reopened.store.runs(), [])
        finally:
            reopened.animation.stop()
            reopened.close()
            reopened.deleteLater()

    def test_scanner_sessions_remain_available_after_radar_rename(self):
        app_data = Path(self.directory.name) / "PHP2ShellHunter"
        scanner_path = app_data / "PHP2Shell Scanner" / "sessions.sqlite3"
        previous = Store(str(scanner_path))
        previous.save_run({"id": "scanner-session", "status": "COMPLETED"})
        previous.close()
        with patch("hunter.gui.QStandardPaths.writableLocation", return_value=str(app_data / "PHP2Shell Radar")):
            reopened = MainWindow()
        try:
            self.assertEqual(reopened.store.runs()[0]["id"], "scanner-session")
        finally:
            reopened.animation.stop()
            reopened.close()
            reopened.deleteLater()

    def test_option_help_and_advanced_dialog_have_no_nested_scroller(self):
        help_button = self.window.help_buttons["Active check if unclear"]
        self.assertIn("memory", help_button.toolTip())
        for title, button in self.window.help_buttons.items():
            self.assertIn("What it does", button.toolTip(), title)
            self.assertIn("Impact", button.toolTip(), title)
            self.assertIn("width='360'", button.toolTip(), title)
        self.assertEqual(help_button.text(), "?")
        self.assertFalse(self.window.findChildren(QScrollArea))
        self.window.show()
        self.app.processEvents()
        help_button.click()
        self.app.processEvents()
        self.assertTrue(QToolTip.isVisible())
        tips = [widget for widget in self.app.topLevelWidgets()
                if widget.isVisible() and widget.metaObject().className() == "QTipLabel"]
        self.assertEqual(len(tips), 1)
        self.assertLessEqual(tips[0].width(), 440)
        QToolTip.hideText()
        self.window.advanced_dialog.resize(764, 480)
        self.window.advanced_dialog.show()
        self.app.processEvents()
        self.assertTrue(self.window.crawl.isVisible())
        self.assertTrue(self.window.verify_tls.isVisible())
        for widget in (self.window.all_addresses, self.window.interval):
            bottom = widget.mapTo(self.window.advanced_dialog, widget.rect().bottomRight())
            self.assertLess(bottom.y(), self.window.advanced_dialog.height() - 36)
        self.window.advanced_dialog.hide()

    def test_status_strip_controls_right_hand_log(self):
        self.assertEqual(self.window.current_status.text(), "Ready to scan")
        self.window.show()
        self.app.processEvents()
        self.window.drawer_btn.setChecked(True)
        self.assertGreaterEqual(self.window.animation.endValue(), 500)
        self.assertEqual(self.window.animation.endValue(), self.window.journal_width())
        self.window.animation.setCurrentTime(self.window.animation.duration())
        self.app.processEvents()
        self.assertGreaterEqual(self.window.drawer.width(), 500)
        self.assertGreaterEqual(self.window.activity.width(), 450)
        self.window.drawer_btn.setChecked(False)
        self.assertEqual(self.window.animation.endValue(), 0)
        self.assertFalse(self.window.drawer_btn.isChecked())
        self.window.resize(1500, 780)
        self.app.processEvents()
        self.window.drawer_btn.setChecked(True)
        self.window.animation.setCurrentTime(self.window.animation.duration())
        self.app.processEvents()
        self.assertEqual(self.window.drawer.width(), 600)
        self.window.drawer_btn.setChecked(False)
        self.window.on_event({"type": "stage", "stage": "DNS / certificate discovery", "total": 3})
        self.app.processEvents()
        self.assertIn("domains", self.window.current_status.text())
        self.assertIn("DNS / certificate discovery", self.window.activity.toPlainText())

    def test_discovery_candidates_do_not_fill_php_results(self):
        window = self.window
        window.targets.setPlainText("example.test")
        old_options = window.options().to_dict()
        old_options["subfinder_path"] = "C:/old/subfinder.exe"
        window.on_event({"type": "started", "id": "candidate-test", "options": old_options})
        for number in range(50):
            window.on_event({"type": "host", "host": f"site{number}.example.test",
                             "ips": ["192.0.2.1"], "source": ["dns"]})
        self.assertEqual(len(window.assets), 100)
        self.assertEqual(window.table.rowCount(), 0)
        self.assertEqual(window.summary.text(), "PHP sites 0/0")
        first, second = list(window.assets)[:2]
        window.on_event({"type": "asset", "asset": dict(window.assets[first], php="NOT_ESTABLISHED", assessment="UNKNOWN")})
        self.assertEqual(window.table.rowCount(), 0)
        window.on_event({"type": "asset", "asset": dict(window.assets[first], php="LIKELY", assessment="UNKNOWN", http_status=200)})
        window.on_event({"type": "asset", "asset": dict(window.assets[second], php="DETECTED", assessment="POTENTIALLY_AFFECTED", http_status=200)})
        self.assertEqual(window.table.rowCount(), 2)
        self.assertEqual(window.summary.text(), "PHP sites 2/2")
        window.on_event({"type": "asset", "asset": dict(window.assets[first], php="NOT_ESTABLISHED", assessment="UNKNOWN")})
        self.assertEqual(window.table.rowCount(), 1)
        self.assertEqual(window.table.item(0, 0).text(), second)
        self.assertEqual(window.summary.text(), "PHP sites 1/1")
        window.on_event({"type": "finished", "status": "COMPLETED"})
        self.assertEqual(window.table.rowCount(), 1)
        window.restore_session(window.run_record)
        self.assertEqual(window.table.rowCount(), 1)
        self.assertEqual(window.table.item(0, 0).text(), second)

    def test_other_sites_can_be_shown_only_after_completion(self):
        window = self.window
        window.targets.setPlainText("example.test")
        window.on_event({"type": "started", "id": "other-sites", "options": window.options().to_dict()})
        php = {"url": "https://php.example.test/", "host": "php.example.test", "php": "DETECTED",
               "assessment": "UNKNOWN", "http_status": 200, "active": {"status": "NOT_RUN"}}
        other = {"url": "https://other.example.test/", "host": "other.example.test",
                 "final_url": "https://other.example.test/", "php": "NOT_ESTABLISHED",
                 "assessment": "UNKNOWN", "http_status": 200}
        upgrade = dict(other, url="http://other.example.test/")
        php_sibling = dict(other, url="http://php.example.test/",
                           final_url="http://php.example.test/", host="php.example.test")
        unreachable = {"url": "https://down.example.test/", "host": "down.example.test",
                       "php": "NOT_ESTABLISHED", "assessment": "UNREACHABLE"}
        for asset in (php, other, upgrade, php_sibling, unreachable):
            window.on_event({"type": "asset", "asset": asset})
        self.assertEqual(window.summary.text(), "PHP sites 1/2")
        self.assertEqual(window.table.rowCount(), 1)
        self.assertFalse(window.show_other.isEnabled())

        window.on_event({"type": "finished", "status": "COMPLETED"})
        self.assertTrue(window.show_other.isEnabled())
        window.show_other.click()
        self.assertEqual(window.table.rowCount(), 3)
        self.assertEqual(window.table.item(0, 0).text(), php["url"])
        self.assertIn("PHP not detected", window.table.item(1, 0).text())
        self.assertEqual(window.table.item(2, 0).text(), other["url"])
        self.assertEqual(window.table.item(2, 1).text(), "200")
        self.assertEqual([window.table.item(2, col).text() for col in range(2, 6)], ["", "", "", ""])
        self.assertIn(upgrade["url"], window.table.item(2, 0).toolTip())
        window.search.setText("other.example.test")
        self.assertTrue(window.table.isRowHidden(0))
        self.assertFalse(window.table.isRowHidden(1))
        self.assertFalse(window.table.isRowHidden(2))
        window.search.setText("absent")
        self.assertTrue(window.table.isRowHidden(1))
        window.search.clear()
        with patch("hunter.gui.QDialog.exec", side_effect=AssertionError("other row opened details")):
            window.show_details(2, 0)
        window.show_other.click()
        self.assertEqual(window.table.rowCount(), 1)
        self.assertEqual(window.summary.text(), "PHP sites 1/2")
        window.restore_session(window.run_record)
        self.assertTrue(window.show_other.isEnabled())
        window.show_other.click()
        self.assertEqual(window.table.rowCount(), 3)

    def test_results_evidence_filter_and_session_restore(self):
        window = self.window
        window.targets.setPlainText("example.test")
        run = {"id": "gui-test", "options": window.options().to_dict(), "started_at": "2026-10-22T10:00:00Z", "status": "COMPLETED"}
        window.on_event({"type": "started", **run})
        asset = {"url": "https://example.test/", "host": "example.test", "php": "DETECTED", "version": "8.4.26", "assessment": "POTENTIALLY_AFFECTED", "source": ["input"], "evidence": [], "cves": {c: {} for c in CVES}, "active": {"status": "NOT_RUN"}, "http_status": 200}
        window.on_event({"type": "asset", "asset": asset})
        self.assertEqual(window.table.rowCount(), 1)

        self.assertEqual([window.table.horizontalHeaderItem(i).text() for i in range(6)],
                         ["Address", "HTTP", "PHP", "Version", "Active check", "Result"])
        self.assertEqual(window.table.item(0, 4).text(), "Off")
        self.assertEqual(window.table.item(0, 5).text(), "Unconfirmed")
        self.assertEqual(window.table.item(0, 5).background().color().name(), "#fff2d5")
        self.assertEqual(window.table.item(0, 4).background().style(), Qt.BrushStyle.NoBrush)
        self.assertTrue(window.table.item(0, 5).textAlignment() & Qt.AlignmentFlag.AlignHCenter)
        for verdict, color in (("Fixed version", "#e1f5ec"), ("At risk", "#fff0e7"),
                               ("Vulnerable", "#fde8eb")):
            window.update_asset(dict(asset, verdict=verdict))
            self.assertEqual(window.table.item(0, 5).text(), verdict)
            self.assertEqual(window.table.item(0, 5).background().color().name(), color)

        for column, samples in {1: ("HTTP", "503"), 2: ("PHP", "Detected"),
                                3: ("Version", "8.4.26-ubuntu1"),
                                4: ("Active check", "Redirects to HTTPS"),
                                5: ("Result", "Fixed version", "Vulnerable")}.items():
            self.assertGreaterEqual(window.table.columnWidth(column),
                                    max(window.table.fontMetrics().horizontalAdvance(text) for text in samples) + 16)

        window.search.setText("absent")
        self.assertTrue(window.table.isRowHidden(0))
        window.search.clear()
        self.assertFalse(window.table.isRowHidden(0))
        window.store.save_asset(run["id"], dict(asset, verdict="Vulnerable"))
        window.restore_session(run)
        self.assertEqual(window.targets.toPlainText(), "example.test")
        self.assertEqual(window.table.rowCount(), 1)
        self.assertEqual(window.table.item(0, 5).text(), "At risk")
        window.store.save_asset(run["id"], dict(asset, verdict="Vulnerable",
                                                  active={"status": "UNPATCHED_SESSION_PATH"}))
        window.restore_session(run)
        self.assertEqual(window.table.item(0, 5).text(), "Vulnerable")
        window.store.save_asset(run["id"], dict(asset, verdict="Unconfirmed",
                                                  proxy=["Cloudflare"], detection_partial=True,
                                                  active={"status": "NOT_RUN"}))
        window.restore_session(run)
        self.assertEqual(window.table.item(0, 5).text(), "At risk")

    def test_active_column_explains_scan_outcomes(self):
        asset = {"url": "https://example.test/", "host": "example.test", "php": "DETECTED",
                 "version": "7.4.33", "verdict": "At risk", "http_status": 200,
                 "active": {"status": "NO_OOM_OBSERVED", "recovery": {"reachable": True}}}
        self.window.update_asset(asset)
        self.assertEqual(self.window.table.item(0, 4).text(), "Checked")
        self.assertIn("does not verify", self.window.table.item(0, 4).toolTip())
        self.window.update_asset(dict(asset, active={"status": "SKIPPED", "reason_code": "ALREADY_CHECKED",
                                                   "checked_at": "https://example.test/"}))
        self.assertEqual(self.window.table.item(0, 4).text(), "Not retested")
        self.assertIn("https://example.test/", self.window.table.item(0, 4).toolTip())
        self.window.update_asset(dict(asset, http_status=500,
                                      active={"status": "SKIPPED", "reason_code": "BASELINE_HTTP_ERROR"}))
        self.assertEqual(self.window.table.item(0, 4).text(), "Page error")
        self.assertIn("HTTP 500", self.window.table.item(0, 4).toolTip())
        self.assertEqual(active_display({"status": "SKIPPED", "reason": "One bounded probe sequence per host/backend per scan."})[0],
                         "Not retested")

    def test_http_upgrade_merges_into_https_and_direct_http_expands(self):
        base = {"host": "example.test", "php": "DETECTED", "version": "7.4.33",
                "assessment": "POTENTIALLY_AFFECTED", "verdict": "At risk", "http_status": 200,
                "content_sha256": "same-page", "reported_versions": ["7.4.33"]}
        https = dict(base, url="https://example.test/", final_url="https://example.test/app",
                     active={"status": "NO_OOM_OBSERVED", "recovery": {"reachable": True}})
        upgrade = dict(base, url="http://example.test/", final_url="https://example.test/app",
                       active={"status": "SKIPPED", "reason_code": "ALREADY_CHECKED",
                               "checked_at": "https://example.test/app"})
        self.window.update_asset(https)
        self.window.update_asset(upgrade)
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 4).text(), "Checked")
        self.window.update_asset(dict(https, active={"status": "SKIPPED", "reason_code": "ALREADY_CHECKED"}))
        self.window.update_asset(dict(upgrade, active={"status": "NO_OOM_OBSERVED", "recovery": {"reachable": True}}))
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 0).text(), "https://example.test/")
        self.assertEqual(self.window.table.item(0, 4).text(), "Checked")
        self.window.update_asset(dict(upgrade, final_url="http://example.test/"))
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.assertEqual(self.window.table.item(0, 0).text(), "▸ http://example.test/")
        self.window.show()
        self.app.processEvents()
        address = self.window.table.item(0, 0)
        QTest.mouseClick(self.window.table.viewport(), Qt.MouseButton.LeftButton,
                         pos=self.window.table.visualItemRect(address).center())
        self.assertEqual(self.window.table.rowCount(), 2)
        self.assertEqual(self.window.table.item(0, 0).text(), "▾ http://example.test/")
        self.assertEqual(self.window.table.item(1, 0).text(), "    ↳ https://example.test/")
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.window.toggle_result_group(0, 0)
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(active_display(upgrade["active"], upgrade)[0], "Redirects to HTTPS")

    def test_only_http_or_https_has_no_expander_and_different_results_stay_separate(self):
        base = {"host": "example.test", "php": "DETECTED", "version": "7.4.33",
                "assessment": "POTENTIALLY_AFFECTED", "verdict": "At risk", "http_status": 200,
                "active": {"status": "NOT_RUN"}}
        http = dict(base, url="http://example.test/", final_url="http://example.test/")
        https = dict(base, url="https://example.test/", final_url="https://example.test/")
        self.window.update_asset(http)
        self.assertEqual(self.window.table.item(0, 0).text(), http["url"])
        self.window.update_asset(https)
        self.assertEqual(self.window.table.item(0, 0).text(), "▸ " + http["url"])
        self.window.update_asset(dict(https, version="8.4.27", verdict="Fixed version"))
        self.assertEqual(self.window.table.rowCount(), 2)
        self.assertEqual(self.window.summary.text(), "PHP sites 2/2")
        self.assertEqual(self.window.table.item(0, 0).text(), http["url"])
        self.assertEqual(self.window.table.item(1, 0).text(), https["url"])
        self.window.update_asset(dict(http, php="NOT_ESTABLISHED"))
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 0).text(), https["url"])

    def test_collapsed_https_address_remains_searchable(self):
        base = {"host": "example.test", "php": "DETECTED", "version": "7.4.33",
                "assessment": "POTENTIALLY_AFFECTED", "verdict": "At risk", "http_status": 200,
                "active": {"status": "NOT_RUN"}}
        self.window.update_asset(dict(base, url="http://example.test/",
                                      final_url="http://example.test/", content_sha256="http-body"))
        self.window.update_asset(dict(base, url="https://example.test/",
                                      final_url="https://example.test/", content_sha256="https-body"))
        self.window.search.setText("https://example.test/")
        self.assertFalse(self.window.table.isRowHidden(0))
        self.window.toggle_result_group(0, 0)
        self.assertFalse(self.window.table.isRowHidden(0))
        self.assertFalse(self.window.table.isRowHidden(1))

    def test_redirect_label_matches_input_and_destination_schemes(self):
        base = {"php": "DETECTED", "version": "7.4.33", "assessment": "POTENTIALLY_AFFECTED",
                "verdict": "At risk", "http_status": 200, "final_url": "https://example.test/",
                "active": {"status": "SKIPPED", "reason_code": "ALREADY_CHECKED",
                           "checked_at": "https://example.test/"}}
        upgrade = dict(base, url="http://example.test/", host="example.test")
        self.window.update_asset(upgrade)
        self.assertEqual(self.window.table.item(0, 0).text(), "https://example.test/")
        self.assertEqual(self.window.table.item(0, 4).text(), "Not retested")
        self.assertIn("HTTP address led to this HTTPS site", self.window.table.item(0, 4).toolTip())
        downgrade = dict(base, url="https://other.example.test/", host="other.example.test",
                         final_url="http://other.example.test/",
                         active={"status": "SKIPPED", "reason_code": "ALREADY_CHECKED",
                                 "checked_at": "http://other.example.test/"})
        self.window.update_asset(downgrade)
        self.assertEqual(self.window.table.item(1, 0).text(), "https://other.example.test/")
        self.assertEqual(self.window.table.item(1, 4).text(), "Redirects to HTTP")

    def test_same_final_destination_merges_dynamic_or_partial_responses(self):
        base = {"host": "example.test", "php": "DETECTED", "version": "8.2.16",
                "assessment": "POTENTIALLY_AFFECTED", "verdict": "Unconfirmed",
                "reported_versions": ["8.2.16"], "http_status": 200,
                "detection_partial": True, "content_sha256": None,
                "final_url": "https://example.test/admin/login"}
        direct = dict(base, url="https://example.test/", active={"status": "SKIPPED",
                    "reason_code": "ALREADY_CHECKED"})
        redirect = dict(base, url="http://example.test/", active={"status": "NO_OOM_OBSERVED",
                      "recovery": {"reachable": True}})
        self.window.update_asset(direct)
        self.window.update_asset(redirect)
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 0).text(), "https://example.test/")
        self.assertEqual(self.window.table.item(0, 4).text(), "Checked")

    def test_redirect_to_path_is_not_a_second_website(self):
        base = {"php": "LIKELY", "version": None, "assessment": "UNKNOWN",
                "verdict": "Unconfirmed", "http_status": 200,
                "active": {"status": "NOT_RUN"}}
        for host in ("example.test", "another.test"):
            root = dict(base, url=f"https://{host}/", final_url=f"https://{host}/",
                        site_url=f"https://{host}/", host=host, source=["input"])
            alias = dict(base, url=f"https://alias.{host}/",
                         final_url=f"https://{host}/section/",
                         site_url=f"https://{host}/section/", host=f"alias.{host}",
                         source=["passive DNS"])
            self.window.update_asset(root)
            self.window.update_asset(alias)
        self.assertEqual(self.window.table.rowCount(), 2)
        self.assertEqual(self.window.summary.text(), "PHP sites 2/2")
        self.assertEqual(self.window.table.item(0, 0).text(), "▸ https://example.test/")
        self.assertEqual(self.window.table.item(1, 0).text(), "▸ https://another.test/")
        self.assertIn("https://alias.example.test/", self.window.table.item(0, 0).toolTip())
        self.window.toggle_result_group(0, 0)
        self.assertEqual(self.window.table.item(1, 0).text(), "    ↳ https://alias.example.test/")
        self.window.toggle_result_group(0, 0)
        self.window.search.setText("alias.example.test")
        self.assertFalse(self.window.table.isRowHidden(0))
        self.assertTrue(self.window.table.isRowHidden(1))

    def test_pages_on_one_site_with_conflicting_patch_signals_use_one_row(self):
        root = {"url": "https://example.test/", "final_url": "https://example.test/",
                "host": "example.test", "http_status": 200, "php": "DETECTED",
                "version": "8.4.27", "reported_versions": ["8.4.27"],
                "assessment": "FIXED_VERSION_REPORTED", "verdict": "Fixed version",
                "active": {"status": "NOT_RUN"}, "evidence": []}
        path = dict(root, url="https://example.test/support/panel-programming",
                    final_url="https://example.test/support/panel-programming",
                    version="8.4.26", reported_versions=["8.4.26"],
                    assessment="POTENTIALLY_AFFECTED", verdict="At risk")
        self.window.update_asset(root)
        self.window.update_asset(path)
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 0).text(), "https://example.test/")
        self.assertEqual(self.window.table.item(0, 3).text(), "—")
        self.assertEqual(self.window.table.item(0, 5).text(), "Unconfirmed")
        self.window.search.setText("panel-programming")
        self.assertFalse(self.window.table.isRowHidden(0))
        self.window.search.clear()
        self.window.copy_result_address(0, 0)
        self.assertEqual(QApplication.clipboard().text(), "https://example.test/")
        self.assertEqual(self.window.visible_result_rows()[0]["Address"], "https://example.test/")
        with patch("hunter.gui.QDialog.exec", return_value=0):
            self.window.show_details(0, 0)

    def test_only_inner_php_page_is_reported_as_site_origin(self):
        path = {"url": "https://example.test/support/panel-programming",
                "final_url": "https://example.test/support/panel-programming",
                "host": "example.test", "http_status": 200, "php": "LIKELY",
                "assessment": "UNKNOWN", "verdict": "Unconfirmed",
                "active": {"status": "NOT_RUN"}, "evidence": []}
        self.window.update_asset(path)
        self.assertEqual(self.window.table.item(0, 0).text(), "https://example.test/")
        self.assertIn(path["url"], self.window.table.item(0, 0).toolTip())
        self.assertEqual(self.window.visible_result_rows()[0]["Address"], "https://example.test/")

    def test_active_positive_on_inner_page_is_not_lost_when_site_is_grouped(self):
        root = {"url": "https://example.test/", "final_url": "https://example.test/",
                "host": "example.test", "http_status": 200, "php": "LIKELY",
                "assessment": "UNKNOWN", "verdict": "Unconfirmed",
                "active": {"status": "NOT_RUN"}, "evidence": []}
        path = dict(root, url="https://example.test/account/",
                    final_url="https://example.test/account/", php="DETECTED",
                    verdict="Vulnerable", active={"status": "UNPATCHED_SESSION_PATH"})
        self.window.update_asset(root)
        self.window.update_asset(path)
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 2).text(), "Detected")
        self.assertEqual(self.window.table.item(0, 4).text(), "Patch gap found")
        self.assertEqual(self.window.table.item(0, 5).text(), "Vulnerable")

    def test_opposite_active_patch_signals_on_one_site_are_unconfirmed(self):
        root = {"url": "https://example.test/", "final_url": "https://example.test/",
                "host": "example.test", "http_status": 200, "php": "DETECTED",
                "assessment": "UNKNOWN", "verdict": "Vulnerable",
                "active": {"status": "UNPATCHED_SESSION_PATH"}}
        path = dict(root, url="https://example.test/account/",
                    final_url="https://example.test/account/", verdict="Unconfirmed",
                    active={"status": "PATCHED_SESSION_PATH"})
        self.window.update_asset(root)
        self.window.update_asset(path)
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 5).text(), "Unconfirmed")
        self.assertIn("conflicting", self.window.table.item(0, 5).toolTip())

    def test_closing_main_window_exits_even_with_another_top_level_widget(self):
        extra = QWidget()
        extra.show()
        self.window.show()
        timeout = QTimer()
        timeout.setSingleShot(True)
        timeout.timeout.connect(self.app.quit)
        timeout.start(1500)
        QTimer.singleShot(0, self.window.close)
        started = time.monotonic()
        self.app.exec()
        timeout.stop()
        extra.close()
        self.assertLess(time.monotonic() - started, 1.0)

    def test_closing_during_scan_stops_worker_then_exits(self):
        async def pending_scan(_options, control, _emit):
            while not control.stopped.is_set():
                await asyncio.sleep(0.01)

        self.window.targets.setPlainText("example.test")
        self.window.show()
        timeout = QTimer()
        timeout.setSingleShot(True)
        timeout.timeout.connect(self.app.quit)
        timeout.start(1500)
        with patch("hunter.gui.run_scan", pending_scan):
            self.window.start_scan()
            QTimer.singleShot(30, self.window.close)
            started = time.monotonic()
            self.app.exec()
        timeout.stop()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertTrue(self.window.close_requested)
        self.assertIsNone(self.window.thread)

    def test_non_php_path_on_php_site_is_not_counted_as_another_website(self):
        root = {"url": "https://example.test/", "final_url": "https://example.test/",
                "host": "example.test", "http_status": 200, "php": "LIKELY",
                "assessment": "UNKNOWN", "verdict": "Unconfirmed"}
        other_path = dict(root, url="https://example.test/section/",
                          final_url="https://example.test/section/", php="NOT_ESTABLISHED")
        self.window.update_asset(root)
        self.window.update_asset(other_path)
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.window.show_other.setEnabled(True)
        self.window.show_other.setChecked(True)
        self.assertEqual(self.window.table.rowCount(), 1)

    def test_redirected_php_row_shows_final_site_and_opens_details(self):
        asset = {"url": "https://dostavka.example.test/", "site_url": "https://delivery.example.test/",
                 "host": "dostavka.example.test", "php": "LIKELY", "version": None,
                 "assessment": "UNKNOWN", "evidence": [{"value": "WordPress fingerprint"}],
                 "active": {"status": "NOT_RUN"}, "http_status": 200}
        self.window.update_asset(asset)
        address = self.window.table.item(0, 0)
        self.assertEqual(address.text(), "https://delivery.example.test/")
        self.assertEqual(address.data(Qt.ItemDataRole.UserRole), asset["url"])
        self.assertIn(asset["url"], address.toolTip())
        with patch("hunter.gui.QDialog.exec", return_value=0):
            self.window.show_details(0, 0)
        self.assertEqual(self.window.table.rowCount(), 1)

    def test_click_copies_visible_address_and_confirms_it(self):
        base = {"host": "example.test", "php": "DETECTED", "version": "8.4.26",
                "assessment": "POTENTIALLY_AFFECTED", "verdict": "At risk", "http_status": 200,
                "active": {"status": "NOT_RUN"}}
        self.window.update_asset(dict(base, url="http://example.test/",
                                      final_url="http://example.test/"))
        self.window.update_asset(dict(base, url="https://example.test/",
                                      final_url="https://example.test/"))
        self.window.show()
        self.app.processEvents()
        QToolTip.hideText()
        parent = self.window.table.item(0, 0)
        QTest.mouseClick(self.window.table.viewport(), Qt.MouseButton.LeftButton,
                         pos=self.window.table.visualItemRect(parent).center())
        self.app.processEvents()
        self.assertEqual(QApplication.clipboard().text(), "http://example.test/")
        self.assertFalse(QToolTip.isVisible())
        self.assertTrue(self.window.copy_toast.isVisible())
        self.assertEqual(self.window.copy_toast.text(), "Copied")
        self.assertTrue(self.window.copy_toast_timer.isActive())
        self.assertEqual(self.window.table.rowCount(), 2)
        self.assertEqual(len(self.window.visible_result_rows()), 2)
        child = self.window.table.item(1, 0)
        QTest.mouseClick(self.window.table.viewport(), Qt.MouseButton.LeftButton,
                         pos=self.window.table.visualItemRect(child).center())
        self.assertEqual(QApplication.clipboard().text(), "https://example.test/")
        self.assertTrue(self.window.copy_toast.isVisible())
        QTest.qWait(1100)
        self.assertFalse(self.window.copy_toast.isVisible())

    def test_export_button_waits_for_scan_end_and_saves_visible_results(self):
        window = self.window
        self.assertFalse(window.export_btn.isEnabled())
        window.targets.setPlainText("example.test")
        window.on_event({"type": "started", "id": "export-test", "options": window.options().to_dict()})
        php = {"url": "https://php.example.test/", "host": "php.example.test",
               "php": "DETECTED", "assessment": "UNKNOWN", "http_status": 200}
        other = {"url": "https://other.example.test/", "host": "other.example.test",
                 "php": "NOT_ESTABLISHED", "assessment": "UNKNOWN", "http_status": 200}
        for asset in (php, other):
            window.on_event({"type": "asset", "asset": asset})
        self.assertFalse(window.export_btn.isEnabled())
        window.on_event({"type": "finished", "status": "COMPLETED"})
        self.assertTrue(window.export_btn.isEnabled())
        path = Path(self.directory.name) / "results.json"
        with patch("hunter.gui.QFileDialog.getSaveFileName", return_value=(str(path), "JSON report (*.json)")):
            window.export_btn.click()
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(report["results"]), 1)
        self.assertEqual(report["results"][0]["Address"], php["url"])
        self.assertEqual(set(report["results"][0]),
                         {"Address", "HTTP", "PHP", "Version", "Active check", "Result"})
        window.show_other.setChecked(True)
        self.assertEqual(len(window.visible_result_rows()), 2)
        window.search.setText("other.example.test")
        self.assertEqual([row["Address"] for row in window.visible_result_rows()], [other["url"]])
        with patch("hunter.gui.QFileDialog.getSaveFileName", return_value=(str(path), "CSV results (*.csv)")):
            window.export_btn.click()
        with path.with_suffix(".csv").open(encoding="utf-8-sig", newline="") as handle:
            exported = list(csv.DictReader(handle))
        self.assertEqual([row["Address"] for row in exported], [other["url"]])
        window.search.clear()
        window.show()
        self.app.processEvents()
        other_row = window.table.item(2, 1)
        QTest.mouseClick(window.table.viewport(), Qt.MouseButton.LeftButton,
                         pos=window.table.visualItemRect(other_row).center())
        self.assertEqual(QApplication.clipboard().text(), other["url"])

    def test_identical_apex_and_www_pages_share_one_result_without_losing_assets(self):
        base = {"php": "DETECTED", "version": "7.2.24", "assessment": "POTENTIALLY_AFFECTED",
                "verdict": "At risk", "http_status": 200, "content_sha256": "same-page",
                "active": {"status": "NOT_RUN"}, "reported_versions": ["7.2.24"]}
        www = dict(base, url="http://www.example.test/", host="www.example.test")
        apex = dict(base, url="http://example.test/", host="example.test")
        self.window.update_asset(www)
        self.window.update_asset(apex)
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.assertEqual(self.window.table.item(0, 0).text(), "▸ " + apex["url"])
        self.assertIn(www["url"], self.window.table.item(0, 0).toolTip())
        self.assertEqual(len(self.window.assets), 2)
        self.window.toggle_result_group(0, 0)
        self.assertEqual(self.window.table.item(1, 0).text(), "    ↳ " + www["url"])
        self.window.toggle_result_group(0, 0)
        self.window.search.setText("www.example.test")
        self.assertFalse(self.window.table.isRowHidden(0))
        with patch("hunter.gui.QDialog.exec", return_value=0):
            self.window.show_details(0, 0)
        self.window.update_asset(dict(www, content_sha256="different-page"))
        self.assertEqual(self.window.table.rowCount(), 2)
        self.window.update_asset(dict(www, content_sha256="same-page", version="8.4.27"))
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 5).text(), "Unconfirmed")
        self.window.update_asset(dict(www, version="7.2.24", connect_ip="192.0.2.5"))
        self.assertEqual(self.window.table.rowCount(), 2)

    def test_protocol_www_redirect_path_and_error_views_form_one_site(self):
        body = "<html><title>Example website</title><body>" + "public website text " * 400 + "</body></html>"
        identity = describe_site(Response("https://example.test/", 200,
                                          {"content-type": "text/html"}, body, 1, truncated=True))
        base = {"php": "LIKELY", "assessment": "UNKNOWN", "verdict": "Unconfirmed",
                "http_status": 200, "site_identity": identity, "active": {"status": "NOT_RUN"}}
        views = [
            dict(base, url="http://example.test/", final_url="http://example.test/"),
            dict(base, url="https://example.test/", final_url="https://example.test/"),
            dict(base, url="http://www.example.test/", final_url="http://www.example.test/"),
            dict(base, url="https://www.example.test/", final_url="https://www.example.test/"),
            dict(base, url="https://example.test/help/", final_url="https://example.test/help/"),
        ]
        for view in views:
            self.window.update_asset(view)
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 0).text(), "▸ http://example.test/")
        self.window.toggle_result_group(0, 0)
        self.assertEqual([self.window.table.item(row, 0).text() for row in range(4)],
                         ["▾ http://example.test/", "    ↳ http://www.example.test/",
                          "    ↳ https://example.test/", "    ↳ https://www.example.test/"])
        self.assertNotIn("/help/", " ".join(self.window.table.item(row, 0).text()
                                                for row in range(4)))
        self.window.update_asset(dict(base, url="http://www.example.test/",
                                      final_url="https://www.example.test/"))
        self.window.update_asset(dict(base, url="http://example.test/",
                                      final_url="https://example.test/"))
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertEqual(self.window.table.item(0, 0).text(), "▸ https://example.test/")
        self.window.toggle_result_group(0, 0)
        self.window.update_asset(dict(base, url="http://example.test/", final_url="http://example.test/",
                                      http_status=521, php="NOT_ESTABLISHED", site_identity=None))
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.assertEqual(self.window.table.rowCount(), 2)

    def test_distinct_apex_www_pages_remain_separate(self):
        first = {"url": "https://example.test/", "final_url": "https://example.test/",
                 "http_status": 200, "php": "LIKELY", "assessment": "UNKNOWN",
                 "verdict": "Unconfirmed", "site_identity": {"title": "main", "sketch": ["a"] * 30}}
        second = dict(first, url="https://www.example.test/", final_url="https://www.example.test/",
                      site_identity={"title": "store", "sketch": ["b"] * 30})
        self.window.update_asset(first)
        self.window.update_asset(second)
        self.assertEqual(self.window.summary.text(), "PHP sites 2/2")

    def test_distinct_http_https_sites_with_shared_layout_remain_separate(self):
        shared = "<p>" + " ".join(f"menu{number}" for number in range(120)) + "</p>"
        for scheme, title, path in (("http", "Internal admin portal", "admin"),
                                    ("https", "Public customer portal", "shop")):
            url = f"{scheme}://example.test/"
            body = (f"<title>{title}</title><link rel=\"canonical\" "
                    f"href=\"https://example.test/{path}\">{shared}<p>{path}</p>")
            asset = {"url": url, **fingerprint(Response(
                         url, 200, {"content-type": "text/html"}, body, 1), ["example.test"]),
                     "php": "LIKELY", "assessment": "UNKNOWN", "verdict": "Unconfirmed"}
            self.window.update_asset(asset)
        self.assertEqual(self.window.summary.text(), "PHP sites 2/2")
        self.assertEqual([row["Address"] for row in self.window.visible_result_rows()],
                         ["http://example.test/", "https://example.test/"])

    def test_two_error_protocols_are_one_host_result(self):
        base = {"http_status": 503, "php": "DETECTED", "assessment": "UNKNOWN",
                "verdict": "Unconfirmed", "active": {"status": "NOT_RUN"}}
        self.window.update_asset(dict(base, url="http://example.test/"))
        self.window.update_asset(dict(base, url="https://example.test/"))
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.assertEqual(self.window.table.rowCount(), 1)
        self.assertNotIn("▸", self.window.table.item(0, 0).text())

    def test_identical_titled_page_aliases_fold_to_actual_host(self):
        base = {"http_status": 200, "php": "NOT_ESTABLISHED", "assessment": "UNKNOWN",
                "verdict": "Unconfirmed", "content_sha256": "one-public-page",
                "site_identity": {"title": "about.example.test", "captured_chars": 1400},
                "scope_roots": ["example.test"]}
        for host in ("www.news.example.test", "about.example.test", "www.direct.example.test"):
            self.window.update_asset(dict(base, url=f"https://{host}/", final_url=f"https://{host}/"))
        self.window.update_asset(dict(base, url="https://direct.example.test/",
                                      final_url="https://direct.example.test/",
                                      content_sha256="different-page",
                                      site_identity={"title": "direct.example.test", "captured_chars": 1400}))
        self.window.show_other.setEnabled(True)
        self.window.show_other.setChecked(True)
        self.assertEqual(self.window.summary.text(), "PHP sites 0/2")
        self.assertEqual(self.window.table.item(1, 0).text(), "▸ https://about.example.test/")
        self.window.toggle_result_group(1, 0)
        self.assertEqual(self.window.table.item(2, 0).text(), "    ↳ https://www.direct.example.test/")
        self.assertEqual(self.window.table.item(3, 0).text(), "    ↳ https://www.news.example.test/")

    def test_identical_titled_pages_from_different_scopes_stay_separate(self):
        base = {"http_status": 200, "php": "NOT_ESTABLISHED", "assessment": "UNKNOWN",
                "verdict": "Unconfirmed", "content_sha256": "shared-template",
                "site_identity": {"title": "app.first.test", "captured_chars": 1400}}
        for host, scope in (("app.first.test", "first.test"),
                            ("app.second.test", "second.test")):
            self.window.update_asset(dict(base, url=f"https://{host}/",
                                          final_url=f"https://{host}/", scope_roots=[scope]))
        self.window.show_other.setEnabled(True)
        self.window.show_other.setChecked(True)
        self.assertEqual(self.window.summary.text(), "PHP sites 0/2")

    def test_redirect_alias_is_visible_copyable_and_exported_from_dropdown(self):
        base = {"http_status": 200, "php": "LIKELY", "assessment": "UNKNOWN",
                "verdict": "Unconfirmed", "active": {"status": "NOT_RUN"}}
        self.window.update_asset(dict(base, url="https://example.test/",
                                      final_url="https://example.test/"))
        self.window.update_asset(dict(base, url="https://www.example.test/",
                                      final_url="https://example.test/",
                                      site_url="https://example.test/"))
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.assertEqual(self.window.table.item(0, 0).text(), "▸ https://example.test/")
        self.window.toggle_result_group(0, 0)
        self.assertEqual(self.window.table.item(1, 0).text(), "    ↳ https://www.example.test/")
        self.window.copy_result_address(1, 0)
        self.assertEqual(QApplication.clipboard().text(), "https://www.example.test/")
        self.assertEqual([row["Address"] for row in self.window.visible_result_rows()],
                         ["https://example.test/", "https://www.example.test/"])

    def test_redirected_subdomain_does_not_hide_direct_www_homepage(self):
        base = {"http_status": 200, "php": "LIKELY", "assessment": "UNKNOWN",
                "verdict": "Unconfirmed", "active": {"status": "NOT_RUN"}}
        self.window.update_asset(dict(base, url="https://example.test/",
                                      final_url="https://example.test/", content_sha256="homepage"))
        self.window.update_asset(dict(base, url="https://support.example.test/",
                                      final_url="https://www.example.test/support/",
                                      site_url="https://www.example.test/support/",
                                      content_sha256="support-page"))
        self.window.update_asset(dict(base, url="https://www.example.test/",
                                      final_url="https://www.example.test/", content_sha256="homepage"))
        self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
        self.window.toggle_result_group(0, 0)
        self.assertEqual([row["Address"] for row in self.window.visible_result_rows()],
                         ["https://example.test/", "https://www.example.test/",
                          "https://support.example.test/"])

    def test_restricted_php_site_remains_visible(self):
        for status in (401, 403):
            with self.subTest(status=status):
                self.window.assets.clear()
                self.window.update_asset({"url": "https://private.example.test/",
                                          "http_status": status, "php": "LIKELY",
                                          "assessment": "UNKNOWN", "verdict": "Unconfirmed",
                                          "active": {"status": "NOT_RUN"}})
                self.assertEqual(self.window.summary.text(), "PHP sites 1/1")
                self.assertEqual(self.window.table.item(0, 1).text(), str(status))

    def test_identical_restricted_protocols_group_but_different_pages_do_not(self):
        base = {"http_status": 401, "php": "NOT_ESTABLISHED", "assessment": "UNKNOWN",
                "verdict": "Unconfirmed", "content_sha256": "same-login-page"}
        self.window.update_asset(dict(base, url="http://private.example.test/"))
        self.window.update_asset(dict(base, url="https://private.example.test/"))
        self.window.show_other.setEnabled(True)
        self.window.show_other.setChecked(True)
        self.assertEqual(self.window.summary.text(), "PHP sites 0/1")
        self.window.toggle_result_group(1, 0)
        self.assertEqual([row["Address"] for row in self.window.visible_result_rows()],
                         ["http://private.example.test/", "https://private.example.test/"])
        self.window.update_asset(dict(base, url="https://private.example.test/",
                                      content_sha256="different-login-page"))
        self.assertEqual(self.window.summary.text(), "PHP sites 0/2")

    def test_foreign_redirect_is_logged_without_becoming_a_discovered_site(self):
        hop = Response("http://alias.example.test/", 302,
                       {"location": "https://unrelated.test/"}, "", 1)
        response = Response("https://unrelated.test/", 200,
                            {"content-type": "text/html"}, "<title>External site</title>", 1,
                            history=[hop])
        asset = {"id": hop.url, "url": hop.url, "host": "alias.example.test",
                 **fingerprint(response, ["example.test"])}
        self.assertTrue(asset["external_redirect"])
        self.assertEqual(asset["site_url"], hop.url)
        self.window.targets.setPlainText("example.test")
        self.window.on_event({"type": "started", "id": "foreign-redirect",
                              "options": self.window.options().to_dict()})
        self.window.on_event({"type": "asset", "asset": asset})
        self.assertEqual(self.window.table.rowCount(), 0)
        self.assertEqual(self.window.summary.text(), "PHP sites 0/0")
        self.assertIn("Outside scan scope: http://alias.example.test/ → https://unrelated.test/",
                      self.window.activity.toPlainText())
        legacy = dict(asset)
        legacy.pop("external_redirect")
        self.window.update_asset(legacy)
        self.assertEqual(self.window.table.rowCount(), 0)

    def test_wildcard_default_page_is_not_a_site_result(self):
        self.window.targets.setPlainText("example.test")
        self.window.on_event({"type": "started", "id": "wildcard-page",
                              "options": self.window.options().to_dict()})
        page = {"id": "https://accounts.example.test/", "url": "https://accounts.example.test/",
                "http_status": 200, "php": "NOT_ESTABLISHED", "assessment": "WILDCARD_RESPONSE",
                "wildcard_ambiguous": True, "wildcard_http_match": True}
        self.window.on_event({"type": "asset", "asset": page})
        self.assertEqual(self.window.table.rowCount(), 0)
        self.assertEqual(self.window.summary.text(), "PHP sites 0/0")
        self.assertIn("Wildcard page: https://accounts.example.test/",
                      self.window.activity.toPlainText())

    def test_empty_http_200_is_journaled_but_not_shown_as_a_site(self):
        self.window.targets.setPlainText("example.test")
        self.window.on_event({"type": "started", "id": "empty-page",
                              "options": self.window.options().to_dict()})
        response = Response("https://blank.example.test/", 200,
                            {"content-type": "text/html"}, "", 1)
        asset = {"id": response.url, "url": response.url, "host": "blank.example.test",
                 **fingerprint(response, ["example.test"])}
        self.window.on_event({"type": "asset", "asset": asset})
        self.assertEqual(self.window.table.rowCount(), 0)
        self.assertEqual(self.window.summary.text(), "PHP sites 0/0")
        self.assertIn("Empty response: https://blank.example.test/",
                      self.window.activity.toPlainText())
        self.window.update_asset(dict(asset, php="DETECTED"))
        self.assertEqual(self.window.table.rowCount(), 1)

    def test_weak_php_hint_on_http_error_is_not_a_site(self):
        self.window.targets.setPlainText("example.test")
        self.window.on_event({"type": "started", "id": "error-page",
                              "options": self.window.options().to_dict()})
        response = Response("https://unknown.example.test/", 404,
                            {"content-type": "text/html"},
                            '<a href="/login.php">Not found</a>', 1)
        asset = {"id": response.url, "url": response.url, "host": "unknown.example.test",
                 **fingerprint(response, ["example.test"])}
        self.assertEqual(asset["php"], "LIKELY")
        self.window.on_event({"type": "asset", "asset": asset})
        self.assertEqual(self.window.table.rowCount(), 0)
        self.assertIn("HTTP error: https://unknown.example.test/",
                      self.window.activity.toPlainText())
        self.window.update_asset(dict(asset, php="DETECTED"))
        self.assertEqual(self.window.table.rowCount(), 1)

    def test_result_fades_on_arrival_and_status_change_only(self):
        self.window.show()
        self.app.processEvents()
        asset = {"url": "https://example.test/", "host": "example.test", "php": "DETECTED",
                 "version": "8.4.26", "assessment": "POTENTIALLY_AFFECTED",
                 "verdict": "At risk", "active": {"status": "NOT_RUN"}, "http_status": 200}
        self.window.update_asset(asset)
        key = self.window.row_group_keys[0]
        self.assertIn(key, self.window.row_fades)
        self.window.row_fades[key].setCurrentTime(420)
        self.assertNotIn(key, self.window.row_fades)
        self.window.update_asset(dict(asset, version="8.4.25"))
        self.assertNotIn(key, self.window.row_fades)
        self.window.update_asset(dict(asset, verdict="Fixed version"))
        self.assertIn(key, self.window.row_fades)

    def test_result_columns_fit_at_minimum_window_width(self):
        self.window.show()
        self.window.resize(780, 560)
        self.app.processEvents()
        self.assertEqual(self.window.table.horizontalScrollBar().maximum(), 0)
        self.assertGreaterEqual(self.window.table.columnWidth(0), 150)

    def test_restore_does_not_reinterpret_legacy_active_option(self):
        self.window.restore_session({"id": "old", "options": {
            "targets": [{"host": "example.test", "url": None}], "active_check": True}})
        self.assertFalse(self.window.active_check.isChecked())
        self.assertFalse(self.window.options().collect_patch_evidence)
        self.assertFalse(self.window.options().active_check)


if __name__ == "__main__":
    unittest.main()
