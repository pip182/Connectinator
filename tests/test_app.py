import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from pathlib import Path
import json
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from connectinator.app import MainWindow
from connectinator.advanced import AdvancedReport, Finding
from connectinator.scanner import Device, Service
from connectinator.monitor import Availability


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.settings = QSettings(str(Path(self.directory.name) / "settings.ini"), QSettings.Format.IniFormat)
        self.settings.setValue("scan/resolve_names", False)
        self.settings.setValue("monitor/enabled", False)
        self.settings.setValue("peers/enabled", False)  # Tests never broadcast on the LAN.
        self.window = MainWindow(self.settings)

    def tearDown(self):
        self.window.close()
        deadline = time.monotonic() + 3
        while (self.window.worker is not None or self.window.availability_worker is not None
               or self.window.advanced_worker is not None) and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        self.assertIsNone(self.window.worker, "Background scan did not stop")
        self.assertIsNone(self.window.availability_worker, "Availability check did not stop")
        self.assertIsNone(self.window.advanced_worker, "Advanced scan did not stop")
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
        self.window.add_device(Device("10.0.0.10", [Service(3306, "MySQL")]))
        self.select("10.0.0.2")
        self.assertTrue(self.window.connect_button.isEnabled())
        self.window.toggle_favorite()
        self.assertEqual(self.window.favorites[device.address], ["VNC:5907"])
        self.window.only_remote.setChecked(True)
        self.assertEqual(self.window.proxy.rowCount(), 1)
        executable = Path(self.directory.name) / "fake viewer.exe"
        executable.touch()
        self.settings.setValue("viewer/path", str(executable))
        with patch("connectinator.app.launch_client") as launch:
            self.window.connect_remote()
            launch.assert_called_once_with(
                "VNC", str(executable), device.address, 5907,
                vnc_style="Double colon", view_only=False, ssh_user="", browser_executable="",
            )
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
        self.assertIn("VNC:5900", self.window.model.cells["10.0.0.2"][7])
        self.assertIn("SSH:22", self.window.model.cells["10.0.0.2"][7])
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
        self.window.endpoint.setCurrentIndex(self.window.endpoint.findData("VNC:5907"))
        self.window.add_device(Device("10.0.0.1", [Service(80, "HTTP")]))
        self.window.flush_updates()
        self.assertEqual(self.window.selected().address, "10.0.0.10")
        self.assertEqual(self.window.endpoint.currentData(), "VNC:5907")

    def test_offline_keeps_services_and_last_seen_and_status_filter(self):
        self.window.add_device(Device("10.0.0.2", [Service(5907, "VNC", True)]))
        self.select("10.0.0.2")
        last_seen = self.window.devices["10.0.0.2"].last_seen
        self.window.availability_found(Availability("10.0.0.2", False, "2026-11-04T15:00:00+00:00"))
        self.window.flush_updates()
        device = self.window.devices["10.0.0.2"]
        self.assertIs(device.online, False)
        self.assertEqual(device.last_seen, last_seen)
        self.assertEqual(device.candidates[0].port, 5907)
        self.assertFalse(device.vnc)
        self.window.status_filter.setCurrentText("Offline")
        self.assertEqual(self.window.proxy.rowCount(), 1)
        self.window.status_filter.setCurrentText("Online")
        self.assertEqual(self.window.proxy.rowCount(), 0)

    def test_startup_and_periodic_checks_use_restored_inventory(self):
        self.window.add_device(Device("10.0.0.2", [Service(5907, "VNC", True)], hostname="shop-pc"))
        self.window.flush_updates()
        self.window.save_inventory()
        self.settings.setValue("monitor/enabled", True)
        calls = []

        async def fake_check(devices, timeout, cancel, on_result, **kwargs):
            calls.append([d.address for d in devices])
            for device in devices:
                on_result(Availability(device.address, True, "2026-11-04T15:00:00+00:00", "TCP"))

        with patch("connectinator.app.check_devices", side_effect=fake_check):
            other = MainWindow(self.settings)
            try:
                self.assertIsNone(other.devices["10.0.0.2"].online)
                deadline = time.monotonic() + 2
                while (not calls or other.availability_worker is not None) and time.monotonic() < deadline:
                    self.app.processEvents()
                    time.sleep(0.01)
                self.assertEqual(calls, [["10.0.0.2"]])
                self.assertIs(other.devices["10.0.0.2"].online, True)
                self.assertTrue(other.monitor_timer.isActive())
                self.assertEqual(other.monitor_timer.interval(), 60000)
                # Fire the next scheduled callback without waiting a minute.
                other.monitor_timer.start(0)
                deadline = time.monotonic() + 2
                while (len(calls) < 2 or other.availability_worker is not None) and time.monotonic() < deadline:
                    self.app.processEvents()
                    time.sleep(0.01)
                self.assertEqual(len(calls), 2)
            finally:
                other.close()
                other.deleteLater()

    def test_monitor_close_cancels_without_losing_saved_devices(self):
        self.window.add_device(Device("10.0.0.2", [Service(5900, "VNC")]))
        self.window.flush_updates()
        started = threading.Event()

        async def waiting_check(devices, timeout, cancel, *args, **kwargs):
            import asyncio
            started.set()
            while not cancel.is_set():
                await asyncio.sleep(0.01)

        with patch("connectinator.app.check_devices", side_effect=waiting_check):
            self.window.start_monitor()
            self.assertTrue(started.wait(1))
            self.window.close()
            deadline = time.monotonic() + 2
            while self.window.availability_worker is not None and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(0.01)
            self.assertIsNone(self.window.availability_worker)
        other = MainWindow(self.settings)
        try:
            self.assertIn("10.0.0.2", other.devices)
        finally:
            other.close()
            other.deleteLater()

    def test_full_scan_preempts_monitor_and_keeps_previous_devices(self):
        self.window.add_device(Device("10.0.0.2", [Service(5900, "VNC")], hostname="saved-pc"))
        self.window.flush_updates()
        started = threading.Event()
        order = []

        async def waiting_check(devices, timeout, cancel, *args, **kwargs):
            import asyncio
            order.append("monitor started")
            started.set()
            while not cancel.is_set():
                await asyncio.sleep(0.01)
            order.append("monitor stopped")

        async def fake_scan(addresses, ports, timeout, cancel, on_device, on_progress, **kwargs):
            order.append("scan started")
            on_device(Device(addresses[0], [Service(5907, "VNC", True)]))
            on_progress(1, 1)

        with patch("connectinator.app.check_devices", side_effect=waiting_check), \
             patch("connectinator.app.scan", side_effect=fake_scan):
            self.window.start_monitor()
            self.assertTrue(started.wait(1))
            self.window.targets.setText("127.0.0.1")
            self.window.start_scan()
            deadline = time.monotonic() + 2
            while (len(order) < 3 or self.window.worker or self.window.availability_worker) and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(0.01)
        self.assertEqual(order, ["monitor started", "monitor stopped", "scan started"])
        self.assertEqual(self.window.devices["10.0.0.2"].hostname, "saved-pc")
        self.assertIn("127.0.0.1", self.window.devices)

    def test_connectinator_peer_is_listed_kept_online_and_released(self):
        from connectinator.inventory import DISCOVERY, NAME
        from connectinator.peers import Peer
        self.window.add_device(Device("10.0.0.20", [Service(22, "SSH", True)]))
        self.window.peer_seen(Peer("10.0.0.21", "a" * 32, "Shop iMac", "macOS 15"))
        self.window.peer_seen(Peer("10.0.0.20", "b" * 32, "Bench PC", "Windows 11"))
        self.window.flush_updates()
        model = self.window.model
        self.assertIs(self.window.devices["10.0.0.21"].online, True)
        self.assertEqual(model.cells["10.0.0.21"][NAME], "Shop iMac")
        self.assertEqual(model.cells["10.0.0.21"][DISCOVERY], "Connectinator peer")
        self.assertEqual(model.cells["10.0.0.20"][DISCOVERY], "TCP + Connectinator")
        self.window.status_filter.setCurrentText("Connectinator peers")
        self.assertEqual(self.window.proxy.rowCount(), 2)
        self.window.search.setText("imac")
        self.assertEqual(self.window.proxy.rowCount(), 1)
        self.select("10.0.0.21")
        self.assertIn("Connectinator running: Shop iMac · macOS 15", self.window.details.toPlainText())
        # Blocked TCP/ping checks don't mark a live peer offline.
        self.window.availability_found(Availability("10.0.0.21", False, "2026-01-01T00:00:00+00:00"))
        self.window.flush_updates()
        self.assertIs(self.window.devices["10.0.0.21"].online, True)
        self.window.peer_lost("10.0.0.21")
        self.window.flush_updates()
        self.assertNotIn("10.0.0.21", model.peers)
        self.assertEqual(model.cells["10.0.0.21"][DISCOVERY], "Saved inventory")
        self.assertIn("10.0.0.21", self.window.devices)  # Kept as an ordinary saved device.

    def test_peer_discovery_setting_starts_and_stops_listener(self):
        self.window.peer_discovery.port = 0  # Ephemeral port; nothing leaves loopback.
        self.window.peer_discovery.targets = []
        self.window.peers_enabled.setChecked(True)
        self.assertTrue(self.window.peer_discovery.running)
        self.window.peers_enabled.setChecked(False)
        self.assertFalse(self.window.peer_discovery.running)
        self.assertFalse(self.settings.value("peers/enabled", type=bool))

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

    def test_context_menu_offers_advanced_scan(self):
        self.window.add_device(Device("10.0.0.30", [Service(22, "SSH", True)]))
        self.select("10.0.0.30")
        index = self.window.table.currentIndex()
        position = self.window.table.visualRect(index).center()
        actions = []
        with patch("connectinator.app.QMenu") as menu_class:
            menu = menu_class.return_value

            def add_action(text):
                action = MagicMock()
                action.text.return_value = text
                actions.append(action)
                return action

            menu.addAction.side_effect = add_action
            self.window.table_context_menu(position)
        self.assertIn("Advanced scan…", [action.text() for action in actions])

    def test_advanced_report_updates_table_details_and_export(self):
        self.window.add_device(Device("10.0.0.30", [Service(22, "SSH", False)]))
        self.select("10.0.0.30")
        report = AdvancedReport(
            "10.0.0.30",
            services=[Service(22, "SSH", True, "SSH-2.0-OpenSSH_9.6"),
                      Service(443, "HTTPS", True, "HTTP/1.1 200 OK")],
            findings=[Finding("Access", "VNC advertises unauthenticated access",
                              "RFB advertised None.", 5900, "warning")],
            fingerprint="TTL suggests a Linux/macOS/Unix-like host",
            ports_scanned=2,
            checked_ports=(22, 443),
            completed_ports=2,
        )
        self.window.advanced_reports[report.address] = report
        self.window._merge_advanced_report(report)
        self.window.flush_updates()
        self.assertIn(443, {service.port for service in self.window.devices[report.address].services})
        self.assertTrue(self.window.devices[report.address].services[0].verified)
        self.assertEqual(self.window.devices[report.address].services[0].source, "advanced")
        self.window.show_device()
        self.assertIn("Advanced scan · 2 ports checked", self.window.details.toPlainText())
        self.assertIn("· advanced", self.window.details.toPlainText())
        self.assertIn("VNC advertises unauthenticated access", self.window.details.toPlainText())

        output = Path(self.directory.name) / "export.json"
        with patch("connectinator.app.QFileDialog.getSaveFileName", return_value=(str(output), "")):
            self.window.export_results()
        exported = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(exported[0]["advanced_scan"]["findings"][0]["severity"], "warning")
        self.assertEqual(exported[0]["advanced_scan"]["ports_scanned"], 2)

    def test_advanced_merge_respects_checked_port_coverage(self):
        address = "10.0.0.40"
        self.window.add_device(Device(address, [
            Service(22, "SSH", True), Service(80, "HTTP", True), Service(9999, "Unknown", False),
        ], complete=False))
        self.select(address)
        report = AdvancedReport(
            address,
            services=[Service(22, "SSH", True, "SSH-2.0")],
            checked_ports=(22, 80),
            completed_ports=2,
            ports_scanned=2,
        )
        self.window._merge_advanced_report(report)
        self.window.flush_updates()
        device = self.window.devices[address]
        self.assertEqual({service.port for service in device.services}, {22, 9999})
        self.assertFalse(device.complete)  # 9999 was never checked.
        self.assertEqual(next(s for s in device.services if s.port == 22).source, "advanced")

        second = AdvancedReport(
            address,
            services=[Service(9999, "Unknown", True)],
            checked_ports=(9999,),
            completed_ports=1,
            ports_scanned=1,
        )
        self.window._merge_advanced_report(second)
        self.window.flush_updates()
        self.assertTrue(self.window.devices[address].complete)

    def test_advanced_update_shows_live_progress(self):
        address = "10.0.0.50"
        self.window.add_device(Device(address, [Service(22, "SSH", False)]))
        self.select(address)
        snapshot = AdvancedReport(
            address,
            services=[Service(22, "SSH", True, "SSH-2.0", "advanced")],
            findings=[Finding("Access", "Old SSH version in banner", "detail", 22, "note")],
            ports_scanned=4,
            completed_ports=2,
            checked_ports=(22,),
            partial=True,
        )
        worker = MagicMock()
        worker.address = address
        self.window.advanced_worker = worker
        try:
            self.window.advanced_update(snapshot)
            self.window.flush_updates()
            text = self.window.details.toPlainText()
            self.assertIn("Advanced scan running…", text)
            self.assertIn("Advanced scan (in progress) · 2/4 ports checked", text)
            self.assertIn("Old SSH version in banner", text)
        finally:
            self.window.advanced_worker = None
            self.window.live_advanced_report = None
            self.window.pending_advanced_update = False
