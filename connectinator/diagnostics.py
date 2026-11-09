"""Explicit packaged-app smoke test; all network probes stay on loopback."""

import json
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import traceback


def self_test(report_filename: str):
    from PySide6.QtCore import QEvent, QSettings, Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication

    from .app import MainWindow
    from .icons import icon
    from .theme import apply_theme

    report_path = Path(report_filename).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {"frozen": bool(getattr(sys, "frozen", False)), "python": sys.version.split()[0], "checks": {}}
    window = None
    app = QApplication.instance() or QApplication([])
    try:
        apply_theme(app)
        app.setFont(QFont("Segoe UI", 10))
        report["checks"]["qtawesome"] = not icon("network-wired").pixmap(32, 32).isNull()
        with tempfile.TemporaryDirectory(prefix="connectinator-self-test-") as directory:
            settings = QSettings(str(Path(directory) / "settings.ini"), QSettings.Format.IniFormat)
            settings.setValue("scan/resolve_names", False)
            settings.setValue("monitor/enabled", False)
            window = MainWindow(settings)
            window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
            window.show()
            app.processEvents()
            report["checks"]["ui_render"] = window.grab().save(str(report_path.with_suffix(".png")))

            class VncHandler(socketserver.BaseRequestHandler):
                def handle(self):
                    self.request.sendall(b"RFB 003.008\n")

            with socketserver.TCPServer(("127.0.0.1", 0), VncHandler) as server:
                server_thread = threading.Thread(target=server.serve_forever, daemon=True)
                server_thread.start()
                try:
                    window.targets.setText("127.0.0.1")
                    window.profile.setCurrentIndex(2)
                    window.ports.setText(str(server.server_address[1]))
                    window.ping.setChecked(False)
                    window.arp.setChecked(False)
                    window.start_scan()
                    deadline = time.monotonic() + 10
                    while window.worker is not None and time.monotonic() < deadline:
                        app.processEvents()
                        time.sleep(0.01)
                    device = window.devices.get("127.0.0.1")
                    report["checks"]["loopback_vnc"] = bool(window.worker is None and device and device.vnc)
                    window.save_inventory()
                    restored = MainWindow(settings)
                    try:
                        saved = restored.devices.get("127.0.0.1")
                        report["checks"]["inventory_reload"] = bool(saved and saved.online is None and saved.candidates)
                        restored.ping.setChecked(False)
                        restored.arp.setChecked(False)
                        restored.start_monitor()
                        deadline = time.monotonic() + 10
                        while restored.availability_worker is not None and time.monotonic() < deadline:
                            app.processEvents()
                            time.sleep(0.01)
                        report["checks"]["availability_check"] = bool(restored.availability_worker is None and
                                                                       restored.devices["127.0.0.1"].online is True)
                    finally:
                        restored.close()
                        if restored.availability_worker:
                            restored.availability_worker.cancel.set()
                            restored.availability_worker.wait(3000)
                            app.processEvents()
                        restored.deleteLater()
                finally:
                    server.shutdown()
                    server_thread.join(timeout=2)

            request = Path(directory) / "arp-request.json"
            result = Path(directory) / "arp-result.jsonl"
            request.write_text(json.dumps({"127.0.0.1": "127.0.0.1"}), encoding="utf-8")
            command = [sys.executable]
            if not getattr(sys, "frozen", False):
                command.extend(["-m", "connectinator"])
            command.extend(["--arp-worker", str(request), str(result)])
            completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=15,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            rows = [json.loads(line) for line in result.read_text(encoding="utf-8").splitlines()]
            report["checks"]["arp_helper"] = bool(completed.returncode == 0 and len(rows) == 1
                                                  and rows[0]["address"] == "127.0.0.1")
            # Release the SQLite connection before TemporaryDirectory removes it.
            window.close()
            app.processEvents()
        report["passed"] = all(report["checks"].values())
    except Exception:
        report["passed"] = False
        report["error"] = traceback.format_exc()
    finally:
        if window is not None:
            window.close()
            if window.worker:
                window.worker.cancel.set()
                window.worker.wait(3000)
            app.processEvents()
            window.deleteLater()
            app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            app.processEvents()
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # As in the normal GUI entry point, keep QApplication alive through SystemExit.
    # Returning first can collect it ahead of the QtAwesome icon/font singletons.
    raise SystemExit(0 if report["passed"] else 1)
