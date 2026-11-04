"""PySide6 desktop interface. All scan I/O runs in a background thread."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import ipaddress
import json
from pathlib import Path
import sys
import threading

from PySide6.QtCore import QSettings, QThread, QTimer, Qt, Signal, Slot
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
from .inventory import ADDRESS, NAME, SERVICES, DeviceModel, DeviceFilter
from .names import HostnameResolver
from .icons import icon
from .theme import ComboBox, apply_theme


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
        self.closing = False
        self.pending_devices: dict[str, Device] = {}
        self.pending_names: dict[str, str] = {}
        self.pending_progress = None
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
        self.model = DeviceModel(self.favorites, self.labels, self)
        self.devices, self.seen = self.model.devices, self.model.seen
        self.proxy = DeviceFilter(self)
        self.proxy.setSourceModel(self.model)
        self.resolver = HostnameResolver(self)
        self.resolver.resolved.connect(self.hostname_found)
        self.setWindowTitle("Connectinator · Network & VNC discovery")
        self.setWindowIcon(icon("network-wired", "#58dfb3"))
        self.resize(1180, 800)
        self.setMinimumSize(900, 640)
        self.build_ui()
        self.load_saved()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(100)
        self.refresh_timer.timeout.connect(self.flush_updates)
        self.refresh_timer.start()

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
        self.viewer_button = QPushButton("Viewer settings")
        self.viewer_button.setIcon(icon("gear"))
        self.viewer_button.clicked.connect(self.viewer_settings)
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
        self.stop_button.setIcon(icon("stop", "#f2a994"))
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
        options.addWidget(QLabel("Connect"))
        options.addWidget(self.timeout)
        options.addWidget(QLabel("Greeting"))
        options.addWidget(self.greeting_timeout)
        panel_layout.addLayout(options)
        discovery = QHBoxLayout()
        discovery.addWidget(self.ping)
        self.arp = QCheckBox("ARP discovery (local subnet)")
        self.arp.setEnabled(sys.platform == "win32")
        self.arp.setChecked(sys.platform == "win32")
        self.arp.setToolTip("Windows: actively resolve local IPv4/MAC addresses even if ping is blocked. Skips routed targets.")
        discovery.addWidget(self.arp)
        self.resolve_names = QCheckBox("Resolve hostnames")
        self.resolve_names.setChecked(self.settings.value("scan/resolve_names", True, type=bool))
        self.resolve_names.toggled.connect(self.toggle_name_resolution)
        discovery.addWidget(self.resolve_names)
        discovery.addStretch()
        panel_layout.addLayout(discovery)
        layout.addWidget(scan_panel)
        if not self.targets.text() and self.network.count() > 1:
            self.network.setCurrentIndex(1)

        self.summary = QLabel()
        self.summary.setObjectName("summary")
        layout.addWidget(self.summary)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by IP, hostname, label, MAC, service, or port…")
        self.search.textChanged.connect(self.filter_rows)
        filters.addWidget(self.search, 1)
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
        for column, width in enumerate((38, 130, 170, 150, 160, 170, 240)):
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
        self.favorite_button.setIcon(icon("fa6.star", "#f2ce75"))
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
        layout.addWidget(self.status)

    def select_network(self, index):
        if target := self.network.itemData(index):
            self.targets.setText(target)

    def select_all_networks(self):
        self.targets.setText(", ".join(self.network.itemData(i) for i in range(1, self.network.count())))

    def load_saved(self):
        self.model.apply([Device(address, [Service(p, "VNC") for p in ports])
                          for address, ports in self.favorites.items()], observed=False)
        self.proxy.invalidate()
        self.update_summary()

    @Slot()
    def start_scan(self):
        if self.worker is not None:
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
        self.pending_devices.clear()
        self.pending_names.clear()
        self.pending_progress = None
        self.scan_warnings.clear()
        self.model.clear()
        self.model.scanning = True
        self.load_saved()
        self.progress.setRange(0, len(addresses))
        self.progress.setValue(0)
        self.status.setText(f"Scanning {len(addresses)} hosts × {len(ports)} TCP ports…")
        self.scan_button.setEnabled(False)
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
        self.stop_button.setEnabled(False)
        if self.closing:
            self.close()

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
        if not self.pending_devices and not self.pending_names:
            return
        selected = self.selected()
        address = selected.address if selected else None
        updates, self.pending_devices = self.pending_devices, {}
        names, self.pending_names = self.pending_names, {}
        for target, name in names.items():
            device = updates.get(target) or self.devices.get(target)
            if device:
                updates[target] = replace(device, hostname=name)
        self.model.apply(list(updates.values()))
        self.proxy.invalidate()
        if address:
            self.select_address(address)
        self.update_summary()
        self.show_device()
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
        self.summary.setText(f"{len(self.seen)} devices found     ·     {self.model.confirmed} verified VNC hosts     ·     {len(self.favorites)} favorites")

    def filter_rows(self):
        selected = self.selected()
        self.proxy.set_filters(self.search.text(), self.only_vnc.isChecked(), self.only_favorites.isChecked())
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
        self.favorite_button.setIcon(icon("star" if favorite else "fa6.star", "#f2ce75"))
        lines = [device.address, "Live scan result" if device.address in self.seen else "Saved favorite; availability has not been checked."]
        for title, value in (("Label", device.label), ("Hostname", device.hostname), ("MAC / ARP", device.mac)):
            if value:
                lines.append(f"{title}: {value}")
        lines.append("Service scan complete." if device.complete else
                     "Service scan still running…" if self.worker and not self.worker.cancel.is_set() else
                     "Service scan incomplete; these are partial results.")
        lines.append("")
        for service in device.services:
            evidence = "protocol verified" if service.verified else "port-based guess; protocol unverified"
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
            launch(executable, device.address, port, self.settings.value("viewer/style", "Double colon"))
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
        if self.worker is not None:
            self.closing = True
            self.stop_scan()
            event.ignore()
        else:
            self.resolver.cancel()
            self.refresh_timer.stop()
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
