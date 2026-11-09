"""PySide6 desktop interface. All scan I/O runs in a background thread."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import ipaddress
import json
import sqlite3
from pathlib import Path
import sys
import shutil
import threading

from PySide6.QtCore import QProcess, QSettings, QStandardPaths, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtGui import QFont
from PySide6.QtNetwork import QAbstractSocket, QNetworkInterface
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox,
    QDoubleSpinBox, QFileDialog, QFormLayout, QFrame, QHBoxLayout,
    QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
    QTableView, QVBoxLayout, QWidget,
)

from .scanner import COMMON_PORTS, VNC_PORTS, Device, Service, parse_ports, parse_targets, scan
from .viewer import find_viewer, launch
from .discovery import arp_targets_for
from .inventory import ADDRESS, NAME, SERVICES, DeviceModel, DeviceFilter, display_time
from .names import HostnameResolver
from .icons import icon
from .theme import ComboBox, apply_theme
from .storage import InventoryStore
from .monitor import Availability, check_devices


def local_networks() -> list[tuple[str, str]]:
    result = []
    seen = set()
    for interface in QNetworkInterface.allInterfaces():
        flags = interface.flags()
        if not flags & QNetworkInterface.InterfaceFlag.IsUp or flags & QNetworkInterface.InterfaceFlag.IsLoopBack:
            continue
        for entry in interface.addressEntries():
            if entry.ip().protocol() != QAbstractSocket.NetworkLayerProtocol.IPv4Protocol:
                continue
            prefix = entry.prefixLength()
            if prefix < 0:
                continue
            # Suggest a manageable local slice for large corporate/VPN networks.
            suggested = max(prefix, 24)
            network = str(ipaddress.IPv4Network(f"{entry.ip().toString()}/{suggested}", strict=False))
            if network not in seen:
                suffix = " (local /24 slice)" if prefix < 24 else ""
                result.append((f"{interface.humanReadableName()} · {network}{suffix}", network))
                seen.add(network)
    result.sort(key=lambda item: (ipaddress.IPv4Network(item[1]).prefixlen >= 31, item[0].lower()))
    return result


def local_interfaces() -> list[tuple[str, int]]:
    result = []
    for interface in QNetworkInterface.allInterfaces():
        flags = interface.flags()
        if not flags & QNetworkInterface.InterfaceFlag.IsUp:
            continue
        if flags & (QNetworkInterface.InterfaceFlag.IsLoopBack | QNetworkInterface.InterfaceFlag.IsPointToPoint):
            continue
        for entry in interface.addressEntries():
            if entry.ip().protocol() == QAbstractSocket.NetworkLayerProtocol.IPv4Protocol:
                result.append((entry.ip().toString(), entry.prefixLength()))
    return result


class ScanThread(QThread):
    device_found = Signal(object)
    progress = Signal(int, int)
    failed = Signal(str)
    notice = Signal(str)

    def __init__(self, addresses, ports, timeout, use_ping, parent=None, *,
                 greeting_timeout=0.5, arp_targets=None, quick_greetings=True):
        super().__init__(parent)
        self.addresses, self.ports = addresses, ports
        self.timeout, self.use_ping = timeout, use_ping
        self.cancel = threading.Event()
        self.error = ""
        self.greeting_timeout = greeting_timeout
        self.arp_targets = arp_targets
        self.quick_greetings = quick_greetings

    def run(self):
        try:
            asyncio.run(scan(
                self.addresses, self.ports, self.timeout, self.cancel,
                self.device_found.emit, self.progress.emit, use_ping=self.use_ping,
                greeting_timeout=self.greeting_timeout, quick_greetings=self.quick_greetings,
                arp_targets=self.arp_targets, on_warning=self.notice.emit,
            ))
        except Exception as exc:
            self.error = str(exc)
            self.failed.emit(self.error)


class AvailabilityThread(QThread):
    result = Signal(object)
    notice = Signal(str)

    def __init__(self, devices, timeout, use_ping, targets, parent=None):
        super().__init__(parent)
        self.devices, self.timeout, self.use_ping, self.targets = devices, timeout, use_ping, targets
        self.cancel = threading.Event()
        self.error = ""

    def run(self):
        try:
            asyncio.run(check_devices(self.devices, self.timeout, self.cancel, self.result.emit,
                                      use_ping=self.use_ping, arp_targets=self.targets,
                                      on_warning=self.notice.emit))
        except Exception as exc:
            self.error = str(exc)


class ViewerDialog(QDialog):
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VNC viewer settings")
        self.resize(620, 190)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.path = QLineEdit(settings.value("viewer/path", "") or find_viewer())
        browse = QPushButton("Browse…")
        browse.setIcon(icon("folder-open"))
        browse.clicked.connect(self.browse)
        path_row = QHBoxLayout()
        path_row.addWidget(self.path, 1)
        path_row.addWidget(browse)
        form.addRow("Viewer executable", path_row)
        self.style = ComboBox()
        self.style.addItems(["Double colon", "Single colon"])
        self.style.setCurrentText(settings.value("viewer/style", "Double colon"))
        form.addRow("Address syntax", self.style)
        layout.addLayout(form)
        hint = QLabel("Double colon: host::5900 (TigerVNC, TightVNC, UltraVNC).\n"
                      "Select single colon if your viewer expects host:5900.\n"
                      "Your viewer handles authentication; passwords are never stored here.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose VNC viewer", self.path.text())
        if path:
            self.path.setText(path)

    def accept(self):
        if not Path(self.path.text().strip()).is_file():
            QMessageBox.warning(self, "Viewer not found", "Choose an existing VNC viewer executable.")
            return
        super().accept()


class MainWindow(QMainWindow):
    def __init__(self, settings: QSettings | None = None):
        super().__init__()
        self.settings = settings if settings is not None else QSettings("Connectinator", "Connectinator")
        self.worker: ScanThread | None = None
        self.availability_worker: AvailabilityThread | None = None
        self.scan_after_monitor = False
        self.closing = False
        self.pending_devices: dict[str, Device] = {}
        self.pending_names: dict[str, str] = {}
        self.pending_progress = None
        self.pending_availability: dict[str, Availability] = {}
        self.dirty: set[str] = set()
        self.store = None
        self.scan_warnings: list[str] = []
        try:
            raw = json.loads(self.settings.value("favorites", "{}"))
            self.favorites = {
                str(ipaddress.IPv4Address(address)): [int(p) for p in ports if 1 <= int(p) <= 65535]
                for address, ports in raw.items()
            }
        except (ValueError, TypeError, AttributeError):
            self.favorites = {}
        try:
            raw = json.loads(self.settings.value("labels", "{}"))
            self.labels = {str(ipaddress.IPv4Address(a)): str(label)[:100] for a, label in raw.items()}
        except (ValueError, TypeError, AttributeError):
            self.labels = {}
        self.tailscale_process = None
        self.model = DeviceModel(self.favorites, self.labels, self)
        self.devices, self.seen = self.model.devices, self.model.seen
        self.proxy = DeviceFilter(self)
        self.proxy.setSourceModel(self.model)
        self.resolver = HostnameResolver(self)
        self.resolver.resolved.connect(self.hostname_found)
        self.setWindowTitle("Connectinator · Network & VNC discovery")
        self.setWindowIcon(icon("network-wired", "#6fd36f"))
        self.resize(1180, 800)
        self.setMinimumSize(900, 640)
        self.build_ui()
        self.load_inventory()
        self.load_saved()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(100)
        self.refresh_timer.timeout.connect(self.flush_updates)
        self.refresh_timer.start()
        self.persist_timer = QTimer(self)
        self.persist_timer.setSingleShot(True)
        self.persist_timer.setInterval(1000)
        self.persist_timer.timeout.connect(self.save_inventory)
        self.monitor_timer = QTimer(self)
        self.monitor_timer.setSingleShot(True)
        self.monitor_timer.timeout.connect(self.start_monitor)
        if self.monitor_enabled.isChecked() and self.devices:
            self.monitor_timer.start(0)

    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(14)
        heading = QHBoxLayout()
        title = QLabel("Connectinator")
        title.setObjectName("title")
        heading.addWidget(title)
        heading.addStretch()
        self.viewer_button = QPushButton("Settings")
        self.viewer_button.setIcon(icon("gear"))
        self.viewer_button.clicked.connect(lambda: self.settings_dialog.exec())
        heading.addWidget(self.viewer_button)
        self.export_button = QPushButton("Export JSON")
        self.export_button.setIcon(icon("file-export"))
        self.export_button.clicked.connect(self.export_results)
        heading.addWidget(self.export_button)
        layout.addLayout(heading)
        subtitle = QLabel("Find devices. Discover services. Connect to VNC.")
        subtitle.setObjectName("muted")
        layout.addWidget(subtitle)

        scan_panel = QFrame()
        scan_panel.setObjectName("panel")
        panel_layout = QVBoxLayout(scan_panel)
        networks = QHBoxLayout()
        networks.addWidget(QLabel("Network"))
        self.network = ComboBox()
        self.network.addItem("Choose a detected network…", "")
        for label, target in local_networks():
            self.network.addItem(icon("network-wired"), label, target)
        self.network.currentIndexChanged.connect(self.select_network)
        networks.addWidget(self.network, 1)
        all_networks = QPushButton("All detected networks")
        all_networks.setIcon(icon("network-wired"))
        all_networks.clicked.connect(self.select_all_networks)
        networks.addWidget(all_networks)
        self.tailscale_button = QPushButton("Tailscale devices")
        self.tailscale_button.setIcon(icon("network-wired"))
        self.tailscale_button.setToolTip("Fill Targets with online Tailscale peers and label them by name")
        self.tailscale_button.clicked.connect(self.load_tailscale)
        networks.addWidget(self.tailscale_button)
        panel_layout.addLayout(networks)

        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Targets"))
        self.targets = QLineEdit(self.settings.value("scan/targets", ""))
        self.targets.setPlaceholderText("192.168.1.0/24, 192.168.2.10-192.168.2.30, or a single IPv4 address")
        target_row.addWidget(self.targets, 1)
        self.scan_button = QPushButton("Scan network")
        self.scan_button.setIcon(icon("magnifying-glass", "#ffffff"))
        self.scan_button.setObjectName("primary")
        self.scan_button.clicked.connect(self.start_scan)
        target_row.addWidget(self.scan_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setIcon(icon("stop", "#f07178"))
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        target_row.addWidget(self.stop_button)
        panel_layout.addLayout(target_row)

        options = QHBoxLayout()
        self.profile = ComboBox()
        self.profile.addItems(["Common services + VNC", "VNC only", "Custom ports"])
        self.profile.setCurrentIndex(int(self.settings.value("scan/profile", 0)))
        self.ports = QLineEdit(self.settings.value("scan/ports", "5900-5909"))
        self.ports.setEnabled(self.profile.currentIndex() == 2)
        self.ports.setToolTip("At most 128 TCP ports; ranges supported. VNC greetings are checked on every open port.")
        self.profile.currentIndexChanged.connect(lambda index: self.ports.setEnabled(index == 2))
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(0.2, 5.0)
        self.timeout.setSingleStep(0.2)
        self.timeout.setValue(float(self.settings.value("scan/timeout", 0.8)))
        self.timeout.setSuffix(" s")
        self.greeting_timeout = QDoubleSpinBox()
        self.greeting_timeout.setRange(0.1, 5.0)
        self.greeting_timeout.setSingleStep(0.1)
        self.greeting_timeout.setValue(float(self.settings.value("scan/greeting_timeout", 0.5)))
        self.greeting_timeout.setSuffix(" s")
        self.ping = QCheckBox("Include ping discovery")
        self.ping.setChecked(True)
        options.addWidget(self.profile)
        options.addWidget(self.ports, 1)
        panel_layout.addLayout(options)
        self.arp = QCheckBox("ARP discovery (local subnet)")
        self.arp.setEnabled(sys.platform == "win32")
        self.arp.setChecked(sys.platform == "win32")
        self.arp.setToolTip("Windows: actively resolve local IPv4/MAC addresses even if ping is blocked. Skips routed targets.")
        self.resolve_names = QCheckBox("Resolve hostnames")
        self.resolve_names.setChecked(self.settings.value("scan/resolve_names", True, type=bool))
        self.resolve_names.toggled.connect(self.toggle_name_resolution)
        layout.addWidget(scan_panel)
        if not self.targets.text() and self.network.count() > 1:
            self.network.setCurrentIndex(1)

        self.summary = QLabel()
        self.summary.setObjectName("summary")
        self.monitor_enabled = QCheckBox("Check saved devices at startup and periodically")
        self.monitor_enabled.setChecked(self.settings.value("monitor/enabled", True, type=bool))
        self.monitor_enabled.toggled.connect(self.monitor_preferences_changed)
        self.monitor_interval = QDoubleSpinBox()
        self.monitor_interval.setDecimals(0)
        self.monitor_interval.setRange(15, 3600)
        self.monitor_interval.setSingleStep(15)
        self.monitor_interval.setValue(float(self.settings.value("monitor/interval", 60)))
        self.monitor_interval.setSuffix(" s")
        self.monitor_interval.valueChanged.connect(self.monitor_preferences_changed)
        self.check_button = QPushButton("Check now")
        self.check_button.setIcon(icon("arrows-rotate"))
        self.check_button.clicked.connect(self.start_monitor)
        heading.insertWidget(heading.indexOf(self.viewer_button), self.check_button)

        # Hosts the scan/monitoring option widgets; kept alive so the rest of the app can read them.
        self.settings_dialog = QDialog(self)
        self.settings_dialog.setWindowTitle("Settings")
        form = QFormLayout(self.settings_dialog)
        form.addRow("Connect timeout", self.timeout)
        form.addRow("VNC greeting timeout", self.greeting_timeout)
        form.addRow(self.ping)
        form.addRow(self.arp)
        form.addRow(self.resolve_names)
        form.addRow(self.monitor_enabled)
        form.addRow("Check every", self.monitor_interval)
        viewer_button = QPushButton("Viewer settings…")
        viewer_button.setIcon(icon("gear"))
        viewer_button.clicked.connect(self.viewer_settings)
        form.addRow(viewer_button)
        close_buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_buttons.rejected.connect(self.settings_dialog.accept)
        form.addRow(close_buttons)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by IP, hostname, label, MAC, service, or port…")
        self.search.textChanged.connect(self.filter_rows)
        filters.addWidget(self.search, 1)
        self.status_filter = ComboBox()
        self.status_filter.addItems(["All devices", "Online", "Offline", "Unchecked"])
        self.status_filter.currentIndexChanged.connect(self.filter_rows)
        filters.addWidget(self.status_filter)
        self.only_vnc = QCheckBox("VNC only")
        self.only_vnc.toggled.connect(self.filter_rows)
        filters.addWidget(self.only_vnc)
        self.only_favorites = QCheckBox("Favorites only")
        self.only_favorites.toggled.connect(self.filter_rows)
        filters.addWidget(self.only_favorites)
        layout.addLayout(filters)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((35, 125, 145, 85, 132, 100, 145, 220, 135)):
            self.table.setColumnWidth(column, width)
        self.table.horizontalHeader().setSectionResizeMode(SERVICES, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setMinimumSectionSize(35)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(ADDRESS, Qt.SortOrder.AscendingOrder)
        self.table.selectionModel().selectionChanged.connect(self.show_device)
        self.table.doubleClicked.connect(self.double_click)
        splitter.addWidget(self.table)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a device to inspect services. Double-click a VNC device to connect.")
        splitter.addWidget(self.details)
        splitter.setSizes([360, 130])
        layout.addWidget(splitter, 1)

        connection = QHBoxLayout()
        self.favorite_button = QPushButton("Save favorite")
        self.favorite_button.setIcon(icon("fa6.star", "#e8b04a"))
        self.favorite_button.setEnabled(False)
        self.favorite_button.clicked.connect(self.toggle_favorite)
        connection.addWidget(self.favorite_button)
        self.label_button = QPushButton("Edit label…")
        self.label_button.setIcon(icon("tag"))
        self.label_button.setEnabled(False)
        self.label_button.clicked.connect(self.edit_label)
        connection.addWidget(self.label_button)
        connection.addStretch()
        connection.addWidget(QLabel("VNC endpoint"))
        self.endpoint = ComboBox()
        self.endpoint.setMinimumWidth(240)
        connection.addWidget(self.endpoint)
        self.view_only = QCheckBox("View only")
        self.view_only.setToolTip("Open the viewer without sending keyboard or mouse input")
        self.view_only.setChecked(self.settings.value("viewer/view_only", False, type=bool))
        self.view_only.toggled.connect(lambda checked: self.settings.setValue("viewer/view_only", checked))
        connection.addWidget(self.view_only)
        self.connect_button = QPushButton("Connect to VNC")
        self.connect_button.setIcon(icon("desktop", "#ffffff"))
        self.connect_button.setObjectName("primary")
        self.connect_button.setEnabled(False)
        self.connect_button.clicked.connect(self.connect_vnc)
        connection.addWidget(self.connect_button)
        layout.addLayout(connection)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setMaximumHeight(6)
        layout.addWidget(self.progress)
        self.status = QLabel("Ready · TCP services are inferred by port unless marked verified.")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        status_row = QHBoxLayout()
        status_row.addWidget(self.status, 1)
        status_row.addWidget(self.summary)
        layout.addLayout(status_row)

    def select_network(self, index):
        if target := self.network.itemData(index):
            self.targets.setText(target)

    def select_all_networks(self):
        self.targets.setText(", ".join(self.network.itemData(i) for i in range(1, self.network.count())))

    def load_tailscale(self):
        if self.tailscale_process is not None:
            return
        program = shutil.which("tailscale") or r"C:\Program Files\Tailscale\tailscale.exe"
        process = QProcess(self)
        process.finished.connect(self.tailscale_finished)
        process.errorOccurred.connect(lambda _e: self.tailscale_finished(-1, None))
        self.tailscale_process = process
        self.tailscale_button.setEnabled(False)
        QTimer.singleShot(5000, lambda: process.kill() if self.tailscale_process is process else None)
        process.start(program, ["status", "--json"])

    def tailscale_finished(self, code, _status):
        process, self.tailscale_process = self.tailscale_process, None
        self.tailscale_button.setEnabled(True)
        if process is None:
            return
        try:
            if code != 0:
                raise ValueError("tailscale status failed (is Tailscale installed and running?)")
            peers = json.loads(bytes(process.readAllStandardOutput()).decode("utf-8", "replace")).get("Peer") or {}
            found = []
            for peer in peers.values():
                if not peer.get("Online"):
                    continue
                addresses = [a for a in peer.get("TailscaleIPs", []) if "." in a]
                if addresses:
                    host = peer.get("HostName") or ""
                    dns = (peer.get("DNSName") or "").rstrip(".")
                    found.append((str(ipaddress.IPv4Address(addresses[0])), dns or host, host))
        except (ValueError, TypeError, AttributeError) as exc:
            QMessageBox.warning(self, "Tailscale", str(exc))
            return
        finally:
            process.deleteLater()
        if not found:
            self.status.setText("No online Tailscale peers found.")
            return
        for address, name, host in found:
            # Don't overwrite custom labels; upgrade ones this button set earlier (bare host name).
            if name and self.labels.get(address, host) == host and self.labels.get(address) != name:
                self.set_label(address, name)
        self.targets.setText(", ".join(address for address, _, _ in found))
        self.status.setText(f"{len(found)} online Tailscale peers added to Targets — press Scan network.")

    def load_saved(self):
        self.model.apply([Device(address, [Service(p, "VNC") for p in ports])
                          for address, ports in self.favorites.items() if address not in self.devices], observed=False)
        self.proxy.invalidate()
        self.update_summary()

    def load_inventory(self):
        if self.settings.format() == QSettings.Format.IniFormat:
            path = Path(self.settings.fileName()).with_suffix(".devices.sqlite3")
        else:
            path = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppLocalDataLocation)) / "devices.sqlite3"
        try:
            self.store = InventoryStore(path)
            devices = self.store.load()
            for device in devices:
                if device.label:
                    self.labels.setdefault(device.address, device.label)
            self.model.apply(devices, observed=False)
            if devices:
                self.status.setText(f"Loaded {len(devices)} saved devices · availability is unchecked until refreshed.")
        except (OSError, sqlite3.Error) as exc:
            if self.store:
                self.store.close()
                self.store = None
            self.status.setText(f"Could not load saved inventory: {exc}")

    def mark_dirty(self, addresses):
        self.dirty.update(addresses)
        if self.store and not self.persist_timer.isActive():
            self.persist_timer.start()

    @Slot()
    def save_inventory(self):
        if not self.store or not self.dirty:
            return
        addresses = self.dirty & self.devices.keys()
        try:
            self.store.save([self.devices[a] for a in addresses])
            self.dirty.difference_update(addresses)
        except (OSError, sqlite3.Error) as exc:
            self.status.setText(f"Could not save inventory: {exc}")
            if not self.closing:
                self.persist_timer.start(3000)

    def monitor_preferences_changed(self, *_):
        self.settings.setValue("monitor/enabled", self.monitor_enabled.isChecked())
        self.settings.setValue("monitor/interval", self.monitor_interval.value())
        self.monitor_timer.stop()
        if not self.monitor_enabled.isChecked():
            if self.availability_worker:
                self.availability_worker.cancel.set()
        elif not self.availability_worker and not self.worker:
            self.monitor_timer.start(0)

    def schedule_monitor(self):
        if not self.closing and self.monitor_enabled.isChecked():
            self.monitor_timer.start(int(self.monitor_interval.value() * 1000))

    @Slot()
    def start_monitor(self):
        self.monitor_timer.stop()
        if self.closing or self.worker or self.availability_worker:
            return
        self.flush_updates()
        if not self.devices:
            self.schedule_monitor()
            return
        devices = list(self.devices.values())
        targets = arp_targets_for(list(self.devices), local_interfaces()) if self.arp.isChecked() else {}
        self.availability_worker = AvailabilityThread(devices, self.timeout.value(), self.ping.isChecked(), targets, self)
        self.availability_worker.result.connect(self.availability_found)
        self.availability_worker.notice.connect(self.status.setText)
        self.availability_worker.finished.connect(self.monitor_finished)
        self.check_button.setEnabled(False)
        self.status.setText(f"Checking availability of {len(devices)} saved devices…")
        self.availability_worker.start()

    @Slot(object)
    def availability_found(self, result):
        self.pending_availability[result.address] = result

    @Slot()
    def monitor_finished(self):
        worker = self.availability_worker
        if worker is None:
            return
        self.flush_updates()
        if worker.error:
            self.status.setText(f"Availability check failed: {worker.error}")
        elif not worker.cancel.is_set():
            self.status.setText(f"Availability updated · {self.model.online_count} online · {self.model.offline_count} offline (no response).")
        self.availability_worker = None
        worker.deleteLater()
        self.check_button.setEnabled(True)
        if self.closing:
            self.close()
        elif self.scan_after_monitor:
            self.scan_after_monitor = False
            self.start_scan()
        else:
            self.schedule_monitor()

    @Slot()
    def start_scan(self):
        if self.worker is not None:
            return
        if self.availability_worker:
            self.scan_after_monitor = True
            self.availability_worker.cancel.set()
            self.status.setText("Stopping availability check before scanning…")
            return
        try:
            addresses = parse_targets(self.targets.text())
            ports = (COMMON_PORTS, VNC_PORTS)[self.profile.currentIndex()] if self.profile.currentIndex() < 2 else parse_ports(self.ports.text())
        except ValueError as exc:
            QMessageBox.warning(self, "Check scan settings", str(exc))
            return
        for key, value in (("targets", self.targets.text()), ("profile", self.profile.currentIndex()),
                           ("ports", self.ports.text()), ("timeout", self.timeout.value()),
                           ("greeting_timeout", self.greeting_timeout.value()),
                           ("resolve_names", self.resolve_names.isChecked())):
            self.settings.setValue(f"scan/{key}", value)
        self.resolver.cancel()
        self.monitor_timer.stop()
        self.flush_updates()
        self.pending_progress = None
        self.scan_warnings.clear()
        self.seen.clear()
        self.model.confirmed = 0
        self.model.scanning = True
        self.progress.setRange(0, len(addresses))
        self.progress.setValue(0)
        self.status.setText(f"Scanning {len(addresses)} hosts × {len(ports)} TCP ports…")
        self.scan_button.setEnabled(False)
        self.check_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        arp_targets = arp_targets_for(addresses, local_interfaces()) if self.arp.isChecked() else {}
        self.worker = ScanThread(addresses, ports, self.timeout.value(), self.ping.isChecked(), self,
                                 greeting_timeout=self.greeting_timeout.value(), arp_targets=arp_targets,
                                 quick_greetings=self.profile.currentIndex() != 2)
        self.worker.device_found.connect(self.add_device)
        self.worker.progress.connect(self.scan_progress)
        self.worker.failed.connect(self.scan_error)
        self.worker.notice.connect(self.scan_notice)
        self.worker.finished.connect(self.scan_finished)
        self.worker.start()

    @Slot(int, int)
    def scan_progress(self, completed, total):
        self.pending_progress = (completed, total)

    @Slot(str)
    def scan_notice(self, message):
        self.scan_warnings.append(message)
        self.status.setText(message)

    @Slot(str)
    def scan_error(self, error):
        self.status.setText(f"Scan failed: {error}")

    @Slot()
    def stop_scan(self):
        self.resolver.cancel()
        if self.worker:
            self.worker.cancel.set()
            self.stop_button.setEnabled(False)
            self.status.setText("Stopping scan…")

    @Slot()
    def scan_finished(self):
        worker = self.worker
        if worker is None:
            return
        self.flush_updates()
        self.model.scanning = False
        for address, device in self.devices.items():
            if not device.complete:
                self.model.refresh(address)
        self.proxy.invalidate()
        message = "Stopped · partial results retained" if worker.cancel.is_set() else "Scan complete"
        self.status.setText(f"Scan failed: {worker.error}" if worker.error else
                            f"{message} · {len(self.seen)} devices responded. Silent/firewalled devices may be missing.")
        if self.scan_warnings:
            self.status.setText(self.status.text() + " " + " ".join(self.scan_warnings))
        if worker.cancel.is_set():
            self.resolver.cancel()
        self.worker = None
        self.show_device()
        worker.deleteLater()
        self.scan_button.setEnabled(True)
        self.check_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if self.closing:
            self.close()
        else:
            self.schedule_monitor()

    @Slot(object)
    def add_device(self, device: Device):
        # Coalesce repeated snapshots for the same IP until the next 100 ms refresh.
        self.pending_devices[device.address] = device

    @Slot(str, str)
    def hostname_found(self, address, name):
        self.pending_names[address] = name

    @Slot()
    def flush_updates(self):
        if self.pending_progress:
            completed, total = self.pending_progress
            self.pending_progress = None
            self.progress.setValue(completed)
            if self.worker and not self.worker.cancel.is_set() and not self.worker.error:
                suffix = " · finishing discovery" if completed == total else ""
                self.status.setText(f"Scanning · {completed} / {total} hosts checked{suffix}")
        if not self.pending_devices and not self.pending_names and not self.pending_availability:
            return
        selected = self.selected()
        address = selected.address if selected else None
        updates, self.pending_devices = self.pending_devices, {}
        names, self.pending_names = self.pending_names, {}
        availability, self.pending_availability = self.pending_availability, {}
        self.model.apply(list(updates.values()))
        statuses = []
        for target, result in availability.items():
            device = self.devices.get(target)
            if device:
                if result.online:
                    # Auto-verify: a VNC port that answered with an RFB greeting is verified;
                    # one that accepted TCP without a greeting loses any stale verification.
                    services = [replace(s, verified=s.port in result.verified_vnc)
                                if s.name == "VNC" and s.port in result.probed_vnc else s
                                for s in device.services]
                    if result.verified_vnc:
                        self.model.seen.add(target)  # counts as verified this session
                else:
                    services = [replace(s, verified=False) for s in device.services]
                statuses.append(replace(device, online=result.online, last_checked=result.checked_at,
                                        last_seen=result.checked_at if result.online else device.last_seen,
                                        mac=result.mac or device.mac, services=services))
        self.model.apply(statuses, observed=False)
        named = []
        for target, name in names.items():
            device = self.devices.get(target)
            if device:
                named.append(replace(device, hostname=name))
        self.model.apply(named, observed=False)
        scrollbar = self.table.verticalScrollBar()
        scroll = scrollbar.value()
        self.proxy.invalidate()
        if address:
            # Re-select without letting the view auto-scroll back to the selected row.
            self.table.setAutoScroll(False)
            try:
                self.select_address(address)
            finally:
                self.table.setAutoScroll(True)
        scrollbar.setValue(scroll)
        self.update_summary()
        self.show_device()
        self.mark_dirty(set(updates) | set(names) | set(availability))
        if self.resolve_names.isChecked() and not self.closing and not (self.worker and self.worker.cancel.is_set()):
            for target in updates:
                self.resolver.lookup(target)

    def toggle_name_resolution(self, enabled):
        self.settings.setValue("scan/resolve_names", enabled)
        if not enabled:
            self.resolver.cancel()
            self.pending_names.clear()
        else:
            for address in self.seen:
                self.resolver.lookup(address)

    def update_summary(self):
        self.summary.setText(f"{len(self.devices)} saved  ·  {self.model.online_count} online  ·  "
                             f"{self.model.offline_count} offline  ·  {self.model.confirmed} verified VNC")

    def filter_rows(self):
        selected = self.selected()
        self.proxy.set_filters(self.search.text(), self.only_vnc.isChecked(), self.only_favorites.isChecked(), self.status_filter.currentText())
        if selected:
            self.select_address(selected.address)
        self.show_device()

    def select_address(self, address: str) -> bool:
        row = self.model.rows.get(address)
        if row is not None:
            index = self.proxy.mapFromSource(self.model.index(row, ADDRESS))
            if index.isValid():
                self.table.setCurrentIndex(index)
                self.table.selectRow(index.row())
                return True
        self.table.clearSelection()
        return False

    def selected(self) -> Device | None:
        rows = self.table.selectionModel().selectedRows(ADDRESS)
        return self.devices.get(rows[0].data()) if rows else None

    @Slot()
    def show_device(self):
        previous = self.endpoint.currentData()
        self.endpoint.clear()
        device = self.selected()
        self.favorite_button.setEnabled(device is not None)
        self.label_button.setEnabled(device is not None)
        self.connect_button.setEnabled(bool(device and device.candidates))
        if not device:
            self.details.clear()
            return
        favorite = device.address in self.favorites
        self.favorite_button.setText("Remove favorite" if favorite else "Save favorite")
        self.favorite_button.setIcon(icon("star" if favorite else "fa6.star", "#e8b04a"))
        state = "Online" if device.online is True else "Offline · no response to configured checks" if device.online is False else "Unchecked"
        lines = [device.address, state, f"Last seen: {display_time(device.last_seen)}",
                 f"Last checked: {display_time(device.last_checked)}",
                 "Current-session scan result" if device.address in self.seen else "Saved service inventory; rescan to verify services."]
        for title, value in (("Label", device.label), ("Hostname", device.hostname), ("MAC / ARP", device.mac)):
            if value:
                lines.append(f"{title}: {value}")
        lines.append("Service scan complete." if device.complete else
                     "Service scan still running…" if self.worker and not self.worker.cancel.is_set() else
                     "Service scan incomplete; these are partial results.")
        lines.append("")
        for service in device.services:
            evidence = "protocol verified" if service.verified else "saved or inferred service; protocol currently unverified"
            lines.append(f"TCP {service.port} · {service.name} · {evidence}")
            if service.banner:
                lines.append(f"  Greeting: {service.banner}")
        if not device.services:
            lines.append("No open scanned ports." if device.complete else "Checking TCP ports…")
        self.details.setPlainText("\n".join(lines))
        for service in device.candidates:
            self.endpoint.addItem(f"{device.address}:{service.port}" + (" · verified" if service.verified else " · unverified"), service.port)
        index = self.endpoint.findData(previous)
        if index >= 0:
            self.endpoint.setCurrentIndex(index)

    def double_click(self, index):
        if index.column() == 0:
            self.toggle_favorite()
        elif index.column() == NAME:
            self.edit_label()
        elif self.selected() and self.selected().candidates:
            self.connect_vnc()

    def toggle_favorite(self):
        device = self.selected()
        if not device:
            return
        if device.address in self.favorites:
            del self.favorites[device.address]
        else:
            self.favorites[device.address] = [s.port for s in device.candidates]
        self.settings.setValue("favorites", json.dumps(self.favorites))
        self.model.refresh(device.address)
        self.filter_rows()
        self.update_summary()

    def edit_label(self):
        device = self.selected()
        if not device:
            return
        text, accepted = QInputDialog.getText(self, "Device label", f"Label for {device.address}",
                                             text=self.labels.get(device.address, ""))
        if accepted:
            self.set_label(device.address, text)

    def set_label(self, address, text):
        text = text.strip()[:100]
        if text:
            self.labels[address] = text
        else:
            self.labels.pop(address, None)
        self.settings.setValue("labels", json.dumps(self.labels))
        self.model.refresh(address)
        self.mark_dirty([address])
        self.filter_rows()

    def viewer_settings(self):
        dialog = ViewerDialog(self.settings, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.settings.setValue("viewer/path", dialog.path.text().strip())
            self.settings.setValue("viewer/style", dialog.style.currentText())
            return True
        return False

    def connect_vnc(self):
        device = self.selected()
        port = self.endpoint.currentData()
        if not device or port is None:
            return
        executable = self.settings.value("viewer/path", "") or find_viewer()
        if not executable or not Path(executable).is_file():
            if not self.viewer_settings():
                return
            executable = self.settings.value("viewer/path", "")
        try:
            launch(executable, device.address, port, self.settings.value("viewer/style", "Double colon"),
                   self.view_only.isChecked())
            self.status.setText(f"Opened VNC viewer for {device.address}:{port}")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not launch viewer", str(exc))

    def export_results(self):
        self.flush_updates()
        filename, _ = QFileDialog.getSaveFileName(self, "Export scan results", "connectinator-results.json", "JSON (*.json)")
        if not filename:
            return
        results = [dict(device.to_dict(), observed_this_scan=address in self.seen,
                        favorite=address in self.favorites) for address, device in sorted(
                            self.devices.items(), key=lambda item: ipaddress.IPv4Address(item[0]))]
        try:
            Path(filename).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
            self.status.setText(f"Exported {len(results)} devices to {filename}")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))

    def closeEvent(self, event):
        self.closing = True
        self.monitor_timer.stop()
        if self.availability_worker:
            self.availability_worker.cancel.set()
        if self.worker is not None or self.availability_worker is not None:
            self.closing = True
            self.stop_scan()
            event.ignore()
        else:
            self.resolver.cancel()
            self.refresh_timer.stop()
            self.flush_updates()
            self.persist_timer.stop()
            self.save_inventory()
            if self.store:
                self.store.close()
                self.store = None
            self.settings.sync()
            event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Connectinator")
    app.setOrganizationName("Connectinator")
    app.setFont(QFont("Segoe UI", 10))
    apply_theme(app)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
