"""Real loopback integration only. Never contacts third-party assets."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from pathlib import Path
import tempfile
import time
import unittest

from hunter.engine import Control, run_scan
from hunter.models import ScanOptions, Target


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<html><form action="upload.php"></form></html>'
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/8.4.26")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        # An intentionally simulated diagnostic, NOT a vulnerable PHP runtime.
        reply = b"Session ID is too long or contains illegal characters" if b"/\r\n--" in body else b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *_):
        pass


class LoopbackTests(unittest.TestCase):
    def test_real_http_engine_flow(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        events = []
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            options = ScanOptions([Target("127.0.0.1", url)], collect_patch_evidence=True, interval=0.01)
            asyncio.run(run_scan(options, Control(), events.append))
            self.assertEqual(events[-1]["status"], "COMPLETED")
            checked = [e["asset"] for e in events if e["type"] == "asset" and e["asset"]["assessment"] != "PENDING"]
            self.assertEqual(len(checked), 1)
            self.assertEqual(checked[0]["php"], "DETECTED")
            self.assertEqual(checked[0]["active"]["status"], "NOT_RUN")
            self.assertEqual(checked[0]["patch_evidence"]["status"], "INCONCLUSIVE")
            self.assertEqual(checked[0]["assessment"], "POTENTIALLY_AFFECTED")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_gui_background_thread_against_loopback(self):
        from PySide6.QtWidgets import QApplication
        from hunter.gui import MainWindow
        app = QApplication.instance() or QApplication([])
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory() as directory:
            window = MainWindow(str(Path(directory) / "gui.sqlite3"))
            try:
                window.targets.setPlainText(f"http://127.0.0.1:{server.server_port}/")
                window.patch_collection.setChecked(True)
                window.start_scan()
                deadline = time.monotonic() + 10
                while window.thread is not None and time.monotonic() < deadline:
                    app.processEvents()
                    time.sleep(0.01)
                self.assertIsNone(window.thread, "Background scan did not finish")
                self.assertTrue(window.start_btn.isEnabled())
                self.assertEqual(window.run_record["status"], "COMPLETED")
                self.assertEqual(window.table.rowCount(), 1)
                self.assertEqual(next(iter(window.assets.values()))["active"]["status"], "NOT_RUN")
                self.assertEqual(next(iter(window.assets.values()))["patch_evidence"]["status"], "INCONCLUSIVE")
            finally:
                if window.thread:
                    window.stop_scan()
                    window.thread.wait(3000)
                    app.processEvents()
                window.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
