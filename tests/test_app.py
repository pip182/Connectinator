import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from pathlib import Path
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from connectinator.app import MainWindow
from connectinator.scanner import Device, Service


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.settings = QSettings(str(Path(self.directory.name) / "settings.ini"), QSettings.Format.IniFormat)
        self.settings.setValue("scan/resolve_names", False)
        self.window = MainWindow(self.settings)

    def tearDown(self):
        self.window.close()
        deadline = time.monotonic() + 3
        while self.window.worker is not None and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        self.assertIsNone(self.window.worker, "Background scan did not stop")
        self.window.deleteLater()
        self.app.processEvents()
        del self.window
        del self.settings
        self.directory.cleanup()

    def select(self, address):
        self.window.flush_updates()
        self.assertTrue(self.window.select_address(address))

    def test_filter_favorite_and_connect_preserve_selected_port(self):
        device = Device("10.0.0.2", [Service(5907, "VNC", True, "RFB 003.008")])
        self.window.add_device(device)
        self.window.add_device(Device("10.0.0.10", [Service(22, "SSH", True)]))
        self.select("10.0.0.2")
        self.assertTrue(self.window.connect_button.isEnabled())
        self.window.toggle_favorite()
        self.assertEqual(self.window.favorites[device.address], [5907])
        self.window.only_vnc.setChecked(True)
        self.assertEqual(self.window.proxy.rowCount(), 1)
        executable = Path(self.directory.name) / "fake viewer.exe"
        executable.touch()
        self.settings.setValue("viewer/path", str(executable))
        with patch("connectinator.app.launch") as launch:
            self.window.connect_vnc()
            launch.assert_called_once_with(str(executable), device.address, 5907, "Double colon")
        self.window.search.setText("no-match")
        self.assertFalse(self.window.connect_button.isEnabled())

    def test_worker_delivers_live_vnc_result_to_gui(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"RFB 003.008\n")

        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            try:
                self.window.targets.setText("127.0.0.1")
                self.window.profile.setCurrentIndex(2)
                self.window.ports.setText(str(server.server_address[1]))
                self.window.ping.setChecked(False)
                self.window.start_scan()
                deadline = time.monotonic() + 5
                while self.window.worker is not None and time.monotonic() < deadline:
                    self.app.processEvents()
                    time.sleep(0.01)
                self.assertIsNone(self.window.worker)
                self.assertEqual(len(self.window.devices["127.0.0.1"].vnc), 1)
                self.assertEqual(self.window.progress.value(), 1)
                self.assertTrue(self.window.scan_button.isEnabled())
            finally:
                server.shutdown()
                server_thread.join()

    def test_saved_favorite_is_never_reported_as_live_verified(self):
        self.window.add_device(Device("10.0.0.2", [Service(5900, "VNC", True)]))
        self.select("10.0.0.2")
        self.window.toggle_favorite()
        other = MainWindow(self.settings)
        try:
            self.assertFalse(other.devices["10.0.0.2"].vnc)
            self.assertFalse(other.seen)
            self.assertEqual(other.devices["10.0.0.2"].candidates[0].port, 5900)
        finally:
            other.close()
            other.deleteLater()

    def test_batched_updates_preserve_labels_hostnames_and_selection(self):
        self.window.add_device(Device("10.0.0.2", [Service(5900, "VNC", True)], complete=False))
        self.assertEqual(self.window.model.rowCount(), 0)
        self.select("10.0.0.2")
        self.window.set_label("10.0.0.2", " Shop workstation ")
        self.window.hostname_found("10.0.0.2", "shop-pc.example")
        self.window.add_device(Device("10.0.0.2", [Service(5900, "VNC", True), Service(22, "SSH", True)]))
        self.window.flush_updates()
        self.assertEqual(self.window.selected().address, "10.0.0.2")
        self.assertEqual(self.window.selected().label, "Shop workstation")
        self.assertEqual(self.window.selected().hostname, "shop-pc.example")
        self.assertEqual(self.window.model.confirmed, 1)
        # A later scanner snapshot must not erase the independently resolved name.
        self.window.add_device(Device("10.0.0.2", [Service(5900, "VNC", True)]))
        self.window.flush_updates()
        self.assertEqual(self.window.selected().hostname, "shop-pc.example")
        for query in ("Shop workstation", "shop-pc.example", "5900"):
            self.window.search.setText(query)
            self.assertEqual(self.window.proxy.rowCount(), 1)
        other = MainWindow(self.settings)
        try:
            self.assertEqual(other.labels["10.0.0.2"], "Shop workstation")
        finally:
            other.close()
            other.deleteLater()

    def test_arp_only_device_is_visible_and_searchable(self):
        self.window.add_device(Device("10.0.0.4", mac="AA:BB:CC:DD:EE:FF", complete=False))
        self.window.flush_updates()
        self.window.search.setText("aa:bb:cc")
        self.assertEqual(self.window.proxy.rowCount(), 1)
        self.select("10.0.0.4")
        self.assertIn("MAC / ARP", self.window.details.toPlainText())
        self.assertFalse(self.window.connect_button.isEnabled())

    def test_numeric_sort_and_selected_endpoint_survive_updates(self):
        self.window.add_device(Device("10.0.0.10", [Service(5900, "VNC", True), Service(5907, "VNC", True)]))
        self.window.add_device(Device("10.0.0.2", [Service(22, "SSH")]))
        self.select("10.0.0.10")
        self.assertEqual(self.window.proxy.index(0, 1).data(), "10.0.0.2")
        self.window.endpoint.setCurrentIndex(self.window.endpoint.findData(5907))
        self.window.add_device(Device("10.0.0.1", [Service(80, "HTTP")]))
        self.window.flush_updates()
        self.assertEqual(self.window.selected().address, "10.0.0.10")
        self.assertEqual(self.window.endpoint.currentData(), 5907)

    def test_window_close_cancels_an_active_scan(self):
        started = threading.Event()

        async def waiting_scan(addresses, ports, timeout, cancel, *args, **kwargs):
            import asyncio
            started.set()
            while not cancel.is_set():
                await asyncio.sleep(0.01)

        with patch("connectinator.app.scan", waiting_scan):
            self.window.targets.setText("127.0.0.1")
            self.window.start_scan()
            self.assertTrue(started.wait(1))
            self.window.close()
            deadline = time.monotonic() + 2
            while self.window.worker is not None and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(0.01)
            self.assertIsNone(self.window.worker)
            self.assertTrue(self.window.closing)
