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
from PySide6.QtGui import QFont, QKeySequence, QShortcut
from PySide6.QtNetwork import QAbstractSocket, QNetworkInterface
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox,
    QDoubleSpinBox, QFileDialog, QFormLayout, QFrame, QHBoxLayout,
    QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
    QTableView, QVBoxLayout, QWidget,
)

from .scanner import COMMON_PORTS, VNC_PORTS, Device, Service, parse_ports, parse_targets, scan
from .advanced import ADVANCED_PORTS, AdvancedReport, advanced_scan
from .remote import (
    BROWSER_KINDS,
    CLIENT_KINDS,
    favorite_ref,
    favorite_service,
    find_client,
    launch_client,
    parse_favorite_ref,
    service_kind,
)
from .viewer import resolve_executable
from .discovery import arp_targets_for
from .inventory import ADDRESS, NAME, SERVICES, DeviceModel, DeviceFilter, display_time
from .names import HostnameResolver
from .icons import icon
from .theme import ComboBox, HelpButton, apply_theme, checkbox_with_help, form_label
from .storage import InventoryStore, utc_now
from .monitor import Availability, check_devices
from .peers import PeerDiscovery


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


class AdvancedThread(QThread):
    report = Signal(object)
    update = Signal(object)
    progress = Signal(int, int)
    failed = Signal(str)

    def __init__(self, address, timeout, parent=None, *, mac="", hostname=""):
        super().__init__(parent)
        self.address, self.timeout = address, timeout
        self.mac, self.hostname = mac, hostname
        self.cancel = threading.Event()
        self.error = ""

    def run(self):
        try:
            result = asyncio.run(advanced_scan(
                self.address, self.timeout, self.cancel.is_set, self.progress.emit,
                mac=self.mac, hostname=self.hostname, on_update=self.update.emit,
            ))
            self.report.emit(result)
        except Exception as exc:
            self.error = str(exc)
            self.failed.emit(self.error)


_GETTING_STARTED = (
    "1. Pick a network or enter Targets (IPv4, subnet, or range).\n"
    "2. Click Scan network. Open ports appear as services are found.\n"
    "3. Select a device, choose a Remote endpoint, and click Connect "
    "(or double-click the row, right-click, or press Ctrl+Enter).\n"
    "4. Right-click a row for Advanced scan: read-only banner, access, and risk checks.\n"
    "5. Use Settings for timeouts, monitoring, and Remote client settings.\n"
    "Hover the ? icons for short tips; click them for longer explanations."
)


def _client_path(settings: QSettings, kind: str) -> str:
    key = f"remote/{kind.lower()}_path"
    configured = settings.value(key, "")
    if configured:
        return configured
    if kind == "VNC":
        return settings.value("viewer/path", "") or find_client(kind)
    if kind in BROWSER_KINDS:
        return settings.value("remote/browser_path", "")
    return find_client(kind)


class RemoteClientsDialog(QDialog):
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Remote client settings")
        self.resize(640, 340)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.paths = {}
        for kind in sorted(CLIENT_KINDS):
            field = QLineEdit(_client_path(settings, kind))
            browse = QPushButton("Browse…")
            browse.setIcon(icon("folder-open"))
            browse.clicked.connect(lambda _checked=False, k=kind, box=field: self._browse(k, box))
            row = QHBoxLayout()
            row.addWidget(field, 1)
            row.addWidget(browse)
            tips = {
                "VNC": "TigerVNC, TightVNC, UltraVNC, or RealVNC viewer executable.",
                "SSH": "OpenSSH ssh or PuTTY putty.exe.",
                "RDP": "mstsc on Windows, or xfreerdp, rdesktop, or Remmina elsewhere.",
                "Telnet": "System telnet client if installed.",
                "WinRM": "PowerShell or pwsh on Windows for Enter-PSSession.",
            }
            form.addRow(
                form_label(
                    f"{kind} client",
                    tips.get(kind, "Path to the client executable."),
                    self,
                    detail=tips.get(kind, "Path to the client executable."),
                ),
                row,
            )
            self.paths[kind] = field
        self.browser = QLineEdit(settings.value("remote/browser_path", ""))
        self.browser.setPlaceholderText("Optional; leave blank for the system default browser")
        browse = QPushButton("Browse…")
        browse.setIcon(icon("folder-open"))
        browse.clicked.connect(lambda: self._browse("Browser", self.browser))
        row = QHBoxLayout()
        row.addWidget(self.browser, 1)
        row.addWidget(browse)
        form.addRow(
            form_label(
                "Web browser (HTTP/HTTPS)",
                "Optional browser for HTTP/HTTPS connects; blank uses the system default.",
                self,
                detail="Leave blank to use the OS default browser. Set a path to force a specific "
                "browser executable (Chromium, Firefox, etc.).",
            ),
            row,
        )
        self.style = ComboBox()
        self.style.addItems(["Double colon", "Single colon"])
        self.style.setCurrentText(settings.value("viewer/style", "Double colon"))
        form.addRow(
            form_label(
                "VNC address syntax",
                "Double colon (host::5900) for TigerVNC-style viewers; single colon for others.",
                self,
                detail="Double colon: 10.0.0.4::5907 passes the exact TCP port to most viewers.\n"
                "Single colon: 10.0.0.4:5907 for viewers that reject double-colon syntax.",
            ),
            self.style,
        )
        self.ssh_user = QLineEdit(settings.value("remote/ssh_user", ""))
        self.ssh_user.setPlaceholderText("Default login name for SSH when empty")
        form.addRow(
            form_label(
                "SSH username",
                "Login name for SSH when empty uses your OS username.",
                self,
                detail="Passed as user@host. PuTTY uses -ssh user@host -P port; OpenSSH uses -p port user@host.",
            ),
            self.ssh_user,
        )
        layout.addLayout(form)
        hint = QLabel(
            "Connectinator launches your installed clients with argument lists only.\n"
            "VNC: double colon host::5900 unless your viewer expects host:5900.\n"
            "HTTP and HTTPS open in your default browser. WinRM starts PowerShell on Windows.\n"
            "Authentication is handled by the client; passwords are never stored here."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self, kind: str, field: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, f"Choose {kind} client", field.text())
        if path:
            field.setText(path)

    def accept(self):
        for kind, field in self.paths.items():
            text = field.text().strip()
            executable = resolve_executable(text) if kind == "VNC" else text
            if text and not Path(executable).is_file():
                QMessageBox.warning(self, "Client not found", f"Choose an existing {kind} client executable.")
                return
        super().accept()


class MainWindow(QMainWindow):
    def __init__(self, settings: QSettings | None = None):
        super().__init__()
        self.settings = settings if settings is not None else QSettings("Connectinator", "Connectinator")
        self.worker: ScanThread | None = None
        self.availability_worker: AvailabilityThread | None = None
        self.advanced_worker: AdvancedThread | None = None
        self.scan_after_monitor = False
        self.advanced_after_monitor: str | None = None
        self.closing = False
        self.pending_devices: dict[str, Device] = {}
        self.pending_names: dict[str, str] = {}
        self.pending_progress = None
        self.pending_availability: dict[str, Availability] = {}
        self.pending_peers: dict[str, object] = {}  # address -> Peer, or None when it left
        self.pending_advanced_report: AdvancedReport | None = None
        self.pending_advanced_update = False
        self.live_advanced_report: AdvancedReport | None = None
        self.advanced_reports: dict[str, AdvancedReport] = {}
        self.dirty: set[str] = set()
        self.store = None
        self.scan_warnings: list[str] = []
        try:
            raw = json.loads(self.settings.value("favorites", "{}"))
            self.favorites = {}
            for address, entries in raw.items():
                refs = []
                for entry in entries:
                    parsed = parse_favorite_ref(entry)
                    if parsed:
                        refs.append(favorite_ref(*parsed))
                if refs:
                    self.favorites[str(ipaddress.IPv4Address(address))] = refs
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
        self.setWindowTitle("Connectinator · Network discovery & remote access")
        self.setWindowIcon(icon("network-wired", "#6fd36f"))
        self.resize(1180, 800)
        self.setMinimumSize(900, 640)
        self.build_ui()
        self.peer_discovery = PeerDiscovery(self)
        self.peer_discovery.peer_seen.connect(self.peer_seen)
        self.peer_discovery.peer_lost.connect(self.peer_lost)
        self.peer_discovery.failed.connect(self.status.setText)
        self.load_inventory()
        self.load_saved()
        if self.peers_enabled.isChecked():
            self.peer_discovery.start()
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
        heading.addWidget(
            HelpButton(
                "How to scan and connect.",
                self,
                title="Getting started",
                detail=_GETTING_STARTED,
            )
        )
        self.viewer_button = QPushButton("Settings")
        self.viewer_button.setIcon(icon("gear"))
        self.viewer_button.clicked.connect(lambda: self.settings_dialog.exec())
        heading.addWidget(self.viewer_button)
        self.export_button = QPushButton("Export JSON")
        self.export_button.setIcon(icon("file-export"))
        self.export_button.clicked.connect(self.export_results)
        heading.addWidget(self.export_button)
        layout.addLayout(heading)
        subtitle = QLabel("Find devices. Discover services. Connect with VNC, SSH, RDP, and more.")
        subtitle.setObjectName("muted")
        layout.addWidget(subtitle)

        scan_panel = QFrame()
        scan_panel.setObjectName("panel")
        panel_layout = QVBoxLayout(scan_panel)
        networks = QHBoxLayout()
        networks.addWidget(
            form_label(
                "Network",
                "Pick a detected interface subnet or fill Targets manually.",
                scan_panel,
                detail="Each entry is a suggested /24 (or smaller) slice on a local interface. "
                "Use All detected networks to scan every suggestion at once.",
            )
        )
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
        self.tailscale_button.clicked.connect(self.load_tailscale)
        networks.addWidget(self.tailscale_button)
        networks.addWidget(
            HelpButton(
                "Load online Tailscale peers into Targets and label them.",
                scan_panel,
                title="Tailscale devices",
                detail="Requires the tailscale CLI. Fills Targets with online peer IPs and applies "
                "Tailscale names as device labels. Does not start a scan automatically.",
            )
        )
        panel_layout.addLayout(networks)

        target_row = QHBoxLayout()
        target_row.addWidget(
            form_label(
                "Targets",
                "IPv4 addresses, subnets, or ranges (comma-separated).",
                scan_panel,
                detail="Examples: 192.168.1.0/24, 10.0.0.10-10.0.0.50, 172.16.5.4\n"
                "At most 4,096 hosts per scan. Large subnets may need a smaller slice.",
            )
        )
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
        options.addWidget(
            form_label(
                "Port profile",
                "Which TCP ports to scan on each host.",
                scan_panel,
                detail="Common services + VNC: well-known ports plus VNC display range.\n"
                "VNC only: ports 5900–5909.\n"
                "Custom ports: your list (up to 128 ports; ranges allowed).",
            )
        )
        self.profile = ComboBox()
        self.profile.addItems(["Common services + VNC", "VNC only", "Custom ports"])
        self.profile.setCurrentIndex(int(self.settings.value("scan/profile", 0)))
        self.ports = QLineEdit(self.settings.value("scan/ports", "5900-5909"))
        self.ports.setEnabled(self.profile.currentIndex() == 2)
        self.profile.currentIndexChanged.connect(lambda index: self.ports.setEnabled(index == 2))
        options.addWidget(self.profile)
        options.addWidget(self.ports, 1)
        options.addWidget(
            HelpButton(
                "Custom port list when Port profile is Custom (ranges, max 128).",
                scan_panel,
                title="Custom ports",
                detail="Examples: 22,80,443,5900-5910\n"
                "VNC greetings are checked on every open port in the list.",
            )
        )
        panel_layout.addLayout(options)
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
        self.arp = QCheckBox("ARP discovery (local subnet)")
        self.arp.setEnabled(sys.platform == "win32")
        self.arp.setChecked(sys.platform == "win32")
        self.resolve_names = QCheckBox("Resolve hostnames")
        self.resolve_names.setChecked(self.settings.value("scan/resolve_names", True, type=bool))
        self.resolve_names.toggled.connect(self.toggle_name_resolution)
        self.peers_enabled = QCheckBox("Find other computers running Connectinator")
        self.peers_enabled.setToolTip("Announce this computer and list other running Connectinator apps "
                                      "on the local network (UDP broadcast, port 47823).")
        self.peers_enabled.setChecked(self.settings.value("peers/enabled", True, type=bool))
        self.peers_enabled.toggled.connect(self.toggle_peers)
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
        heading.insertWidget(
            heading.indexOf(self.viewer_button),
            HelpButton(
                "Run availability checks on saved devices now.",
                self,
                title="Check now",
                detail="Probes a few known ports per device, then ping/ARP if enabled. "
                "Does not repeat the full port scan.",
            ),
        )

        # Hosts the scan/monitoring option widgets; kept alive so the rest of the app can read them.
        self.settings_dialog = QDialog(self)
        self.settings_dialog.setWindowTitle("Settings")
        form = QFormLayout(self.settings_dialog)
        form.addRow(
            form_label(
                "Connect timeout",
                "Seconds to wait for each TCP connect during a scan.",
                self.settings_dialog,
                detail="Independent from greeting timeout. Increase on slow or distant networks.",
            ),
            self.timeout,
        )
        form.addRow(
            form_label(
                "VNC greeting timeout",
                "Seconds to read an RFB greeting on open VNC ports.",
                self.settings_dialog,
                detail="A short read can leave VNC as unverified even when the port is open.",
            ),
            self.greeting_timeout,
        )
        form.addRow(
            checkbox_with_help(
                self.ping,
                "ICMP ping can discover hosts with no open scanned ports.",
                self.settings_dialog,
                detail="Uses the system ping utility. TCP discovery still works if ping is off.",
            )
        )
        form.addRow(
            checkbox_with_help(
                self.arp,
                "Windows: resolve local IPv4/MAC even when ping and TCP fail.",
                self.settings_dialog,
                detail="Active ARP on directly connected subnets only. Skips routed targets. "
                "Not available on macOS/Linux.",
            )
        )
        form.addRow(
            checkbox_with_help(
                self.resolve_names,
                "Reverse DNS for discovered IPs (bounded concurrency).",
                self.settings_dialog,
                detail="Up to eight lookups at a time, ~2 s UI deadline each. Failures are cached briefly.",
            )
        )
        form.addRow(
            checkbox_with_help(
                self.peers_enabled,
                "Find other computers running Connectinator on this network.",
                self.settings_dialog,
                detail="Announce this computer over UDP 47823 and list other running copies on "
                "the same subnet. No scan data, labels, or VNC credentials are shared.",
            )
        )
        form.addRow(
            checkbox_with_help(
                self.monitor_enabled,
                "Background reachability checks for saved devices.",
                self.settings_dialog,
                detail="Runs after startup and on a repeating interval. Full scans cancel an active check.",
            )
        )
        form.addRow(
            form_label(
                "Check every",
                "Seconds after the previous check finishes before the next one.",
                self.settings_dialog,
                detail="Default 60 s. Range 15 s to 1 hour. Use Check now for an immediate run.",
            ),
            self.monitor_interval,
        )
        remote_button = QPushButton("Remote client settings…")
        remote_button.setIcon(icon("gear"))
        remote_button.clicked.connect(self.remote_client_settings)
        form.addRow(
            form_label(
                "Remote clients",
                "Paths and options for VNC, SSH, RDP, Telnet, browser, and WinRM.",
                self.settings_dialog,
                detail="Connectinator only launches installed clients with argument lists; "
                "passwords are never stored here.",
            ),
            remote_button,
        )
        close_buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close_buttons.rejected.connect(self.settings_dialog.accept)
        form.addRow(close_buttons)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by IP, hostname, label, MAC, service, or port…")
        self.search.textChanged.connect(self.filter_rows)
        filters.addWidget(self.search, 1)
        filters.addWidget(
            HelpButton(
                "Filter the device list.",
                self,
                title="Filters",
                detail="Search matches IP, hostname, label, MAC, services, and ports.\n"
                "Status limits Online/Offline/Unchecked.\n"
                "Remote services only hides devices with nothing to connect to.\n"
                "Favorites only shows starred devices.",
            )
        )
        self.status_filter = ComboBox()
        self.status_filter.addItems(["All devices", "Online", "Offline", "Unchecked", "Connectinator peers"])
        self.status_filter.currentIndexChanged.connect(self.filter_rows)
        filters.addWidget(self.status_filter)
        self.only_remote = QCheckBox("Remote services only")
        self.only_remote.toggled.connect(self.filter_rows)
        filters.addWidget(
            checkbox_with_help(
                self.only_remote,
                "Show only devices with VNC, SSH, RDP, web, or other connectable services.",
                self,
            )
        )
        self.only_favorites = QCheckBox("Favorites only")
        self.only_favorites.toggled.connect(self.filter_rows)
        filters.addWidget(
            checkbox_with_help(
                self.only_favorites,
                "Show only devices saved as favorites.",
                self,
            )
        )
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
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.table_context_menu)
        splitter.addWidget(self.table)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText("Select a device to inspect services. Double-click a row to connect.")
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
        connection.addWidget(
            form_label(
                "Remote endpoint",
                "Service and port to open with Connect.",
                self,
                detail="Lists connectable services found on the selected device. "
                "Favorites restore the saved protocol:port when you reselect the device.",
            )
        )
        self.endpoint = ComboBox()
        self.endpoint.setMinimumWidth(280)
        self.endpoint.currentIndexChanged.connect(self._endpoint_changed)
        connection.addWidget(self.endpoint)
        self.view_only = QCheckBox("View only")
        self.view_only.setChecked(self.settings.value("viewer/view_only", False, type=bool))
        self.view_only.toggled.connect(lambda checked: self.settings.setValue("viewer/view_only", checked))
        connection.addWidget(
            checkbox_with_help(
                self.view_only,
                "VNC: open the viewer without sending keyboard or mouse input.",
                self,
                title="View only",
            )
        )
        self.connect_button = QPushButton("Connect")
        self.connect_button.setIcon(icon("desktop", "#ffffff"))
        self.connect_button.setObjectName("primary")
        self.connect_button.setEnabled(False)
        self.connect_button.clicked.connect(self.connect_remote)
        connection.addWidget(self.connect_button)
        connection.addWidget(
            HelpButton(
                "Launch the selected remote client (Ctrl+Enter).",
                self,
                title="Connect",
                detail="Opens VNC, SSH, RDP, Telnet, a browser for HTTP/S, or PowerShell for WinRM.\n"
                "Double-click a table row or use the row context menu to connect quickly.",
            )
        )
        QShortcut(QKeySequence("Ctrl+Return"), self, self.connect_remote)
        QShortcut(QKeySequence("Ctrl+Enter"), self, self.connect_remote)
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
        self.model.apply([
            Device(address, [favorite_service(*parsed) for ref in refs if (parsed := parse_favorite_ref(ref))])
            for address, refs in self.favorites.items() if address not in self.devices
        ], observed=False)
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
        elif not self.availability_worker and not self.worker and not self.advanced_worker:
            self.monitor_timer.start(0)

    def schedule_monitor(self):
        if not self.closing and not self.advanced_worker and self.monitor_enabled.isChecked():
            self.monitor_timer.start(int(self.monitor_interval.value() * 1000))

    @Slot()
    def start_monitor(self):
        self.monitor_timer.stop()
        if self.closing or self.worker or self.availability_worker or self.advanced_worker:
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
            return
        advanced_address = self.advanced_after_monitor
        self.advanced_after_monitor = None
        if advanced_address:
            self.start_advanced_scan(advanced_address)
        elif self.scan_after_monitor:
            self.scan_after_monitor = False
            self.start_scan()
        else:
            self.schedule_monitor()

    @Slot()
    def start_scan(self):
        if self.worker is not None or self.advanced_worker is not None:
            self.status.setText("A scan is already running; stop it before starting another.")
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
        elif self.advanced_worker:
            self.advanced_worker.cancel.set()
            self.stop_button.setEnabled(False)
            self.status.setText("Stopping advanced scan…")

    @Slot()
    def start_advanced_scan(self, address: str | None = None):
        if not address:
            device = self.selected()
            address = device.address if device else ""
        if not address or address not in self.devices:
            self.status.setText("Select a device before running an advanced scan.")
            return
        if self.worker is not None or self.advanced_worker is not None:
            self.status.setText("A scan is already running; stop it before starting another.")
            return
        if self.availability_worker:
            self.advanced_after_monitor = address
            self.scan_after_monitor = False
            self.availability_worker.cancel.set()
            self.status.setText("Stopping availability check before the advanced scan…")
            return
        device = self.devices[address]
        self.flush_updates()
        self.resolver.cancel()
        self.monitor_timer.stop()
        self.pending_progress = None
        self.pending_advanced_report = None
        self.pending_advanced_update = False
        self.live_advanced_report = None
        self.advanced_reports.pop(address, None)
        self.progress.setRange(0, len(ADVANCED_PORTS))
        self.progress.setValue(0)
        self.status.setText(f"Advanced read-only scan of {address} · {len(ADVANCED_PORTS)} ports…")
        self.scan_button.setEnabled(False)
        self.check_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.advanced_worker = AdvancedThread(
            address, self.timeout.value(), self, mac=device.mac, hostname=device.hostname,
        )
        self.advanced_worker.progress.connect(self.scan_progress)
        self.advanced_worker.update.connect(self.advanced_update)
        self.advanced_worker.report.connect(self.advanced_report_ready)
        self.advanced_worker.failed.connect(self.advanced_error)
        self.advanced_worker.finished.connect(self.advanced_finished)
        self.advanced_worker.start()

    @Slot(object)
    def advanced_report_ready(self, report: AdvancedReport):
        self.pending_advanced_report = report

    @Slot(object)
    def advanced_update(self, report: AdvancedReport):
        self.live_advanced_report = report
        self.pending_advanced_update = True
        self.flush_updates()

    @Slot(str)
    def advanced_error(self, error):
        self.status.setText(f"Advanced scan failed: {error}")

    @Slot()
    def advanced_finished(self):
        worker = self.advanced_worker
        if worker is None:
            return
        self.flush_updates()
        report = self.pending_advanced_report
        self.pending_advanced_report = None
        if report is not None:
            self.advanced_reports[report.address] = report
            self._merge_advanced_report(report)
            self.select_address(report.address)
            verb = "stopped" if report.partial or worker.cancel.is_set() else "complete"
            self.status.setText(
                f"Advanced scan {verb} for {report.address} · {len(report.services)} open ports · "
                f"{len(report.findings)} observations."
            )
        elif worker.error:
            self.status.setText(f"Advanced scan failed: {worker.error}")
        else:
            self.status.setText("Advanced scan stopped.")
        self.advanced_worker = None
        worker.deleteLater()
        self.pending_advanced_update = False
        self.live_advanced_report = None
        self.show_device()
        self.scan_button.setEnabled(True)
        self.check_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if self.closing:
            self.close()
        else:
            self.schedule_monitor()

    def _merge_advanced_report(self, report: AdvancedReport):
        device = self.pending_devices.get(report.address) or self.devices.get(report.address)
        if device is None:
            return
        found = {service.port: service for service in report.services}
        checked = set(report.checked_ports)
        services = {}
        for service in device.services:
            # A checked port with no result was closed or filtered during this run.
            if service.port in checked and service.port not in found:
                continue
            services[service.port] = service
        for port, service in found.items():
            services[port] = replace(service, source="advanced")
        now = utc_now()
        updated = replace(
            device,
            services=[services[port] for port in sorted(services)],
            complete=device.complete or all(
                service.source == "advanced" or service.port in checked
                for service in services.values()
            ),
            online=True if report.reachable else device.online,
            last_checked=now,
            last_seen=now if report.reachable else device.last_seen,
        )
        if report.reachable:
            self.seen.add(report.address)
        self.pending_devices[report.address] = updated
        self.mark_dirty([report.address])
        self.flush_updates()

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

    @Slot(object)
    def peer_seen(self, peer):
        self.pending_peers[peer.address] = peer

    @Slot(str)
    def peer_lost(self, address):
        self.pending_peers[address] = None

    def toggle_peers(self, enabled):
        self.settings.setValue("peers/enabled", enabled)
        if enabled:
            self.peer_discovery.start()
        else:
            self.peer_discovery.stop()

    @Slot(str, str)
    def hostname_found(self, address, name):
        self.pending_names[address] = name

    @Slot()
    def flush_updates(self):
        if self.pending_progress:
            completed, total = self.pending_progress
            self.pending_progress = None
            self.progress.setValue(completed)
            if self.advanced_worker and not self.advanced_worker.cancel.is_set():
                self.status.setText(f"Advanced scan · {completed} / {total} ports checked")
            elif self.worker and not self.worker.cancel.is_set() and not self.worker.error:
                suffix = " · finishing discovery" if completed == total else ""
                self.status.setText(f"Scanning · {completed} / {total} hosts checked{suffix}")
        if not (self.pending_devices or self.pending_names or self.pending_availability or self.pending_peers):
            if self.pending_advanced_update:
                self.pending_advanced_update = False
                self.show_device()
            return
        selected = self.selected()
        address = selected.address if selected else None
        updates, self.pending_devices = self.pending_devices, {}
        names, self.pending_names = self.pending_names, {}
        availability, self.pending_availability = self.pending_availability, {}
        peers, self.pending_peers = self.pending_peers, {}
        self.model.apply(list(updates.values()))
        peer_devices = []
        for target, peer in peers.items():
            if peer is None:
                if self.model.peers.pop(target, None) is not None:
                    self.model.refresh(target)
                continue
            self.model.peers[target] = peer
            device = self.devices.get(target) or Device(target)
            now = utc_now()
            peer_devices.append(replace(device, online=True, last_seen=now, last_checked=now))
        self.model.apply(peer_devices, observed=False)
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
                elif target in self.model.peers:
                    continue  # Its beacon is fresher evidence than blocked TCP/ping checks.
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
        self.pending_advanced_update = False
        self.show_device()
        self.mark_dirty(set(updates) | set(names) | set(availability) | {d.address for d in peer_devices})
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
                             f"{self.model.offline_count} offline  ·  {self.model.confirmed} verified VNC"
                             + (f"  ·  {len(self.model.peers)} Connectinator peers" if self.model.peers else ""))

    def filter_rows(self):
        selected = self.selected()
        self.proxy.set_filters(self.search.text(), self.only_remote.isChecked(), self.only_favorites.isChecked(), self.status_filter.currentText())
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
        self.connect_button.setEnabled(bool(device and device.connectable))
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
        if peer := self.model.peers.get(device.address):
            lines.append(f"Connectinator running: {peer.name}" + (f" · {peer.platform}" if peer.platform else ""))
        for title, value in (("Label", device.label), ("Hostname", device.hostname), ("MAC / ARP", device.mac)):
            if value:
                lines.append(f"{title}: {value}")
        advanced_active = bool(self.advanced_worker and self.advanced_worker.address == device.address)
        if advanced_active:
            lines.append("Advanced scan running…")
        elif device.complete:
            lines.append("Service scan complete.")
        elif self.worker and not self.worker.cancel.is_set():
            lines.append("Service scan still running…")
        else:
            lines.append("Service scan incomplete; these are partial results.")
        lines.append("")
        for service in device.services:
            evidence = "protocol verified" if service.verified else "saved or inferred service; protocol currently unverified"
            source = f" · {service.source}" if service.source and service.source != "scan" else ""
            kind = service_kind(service)
            connect = f" · connectable as {kind}" if kind else ""
            lines.append(f"TCP {service.port} · {service.name} · {evidence}{source}{connect}")
            if service.banner:
                lines.append(f"  Greeting: {service.banner}")
        if not device.services:
            lines.append("No open scanned ports." if device.complete else "Checking TCP ports…")
        report = self.live_advanced_report if advanced_active else self.advanced_reports.get(device.address)
        if report:
            lines.append("")
            if advanced_active:
                done = report.completed_ports or report.ports_scanned
                lines.append(f"Advanced scan (in progress) · {done}/{report.ports_scanned} ports checked")
            else:
                lines.append(f"Advanced scan · {report.ports_scanned} ports checked"
                             + (" · stopped early" if report.partial else ""))
            if report.fingerprint:
                lines.append(f"Fingerprint (low confidence): {report.fingerprint}")
            for finding in report.findings:
                location = f" · TCP {finding.port}" if finding.port else ""
                lines.append(f"{finding.severity.upper()} · {finding.category} · {finding.title}{location}")
                lines.append(f"  {finding.detail}")
        self.details.setPlainText("\n".join(lines))
        for service in device.connectable:
            kind = service_kind(service) or service.name
            label = (f"{kind} · {device.address}:{service.port}"
                     + (" · verified" if service.verified else " · unverified"))
            self.endpoint.addItem(label, f"{kind}:{service.port}")
        preferred = previous if isinstance(previous, str) else None
        if device.address in self.favorites and self.favorites[device.address]:
            preferred = preferred or self.favorites[device.address][0]
        index = self.endpoint.findData(preferred) if preferred else -1
        if index >= 0:
            self.endpoint.setCurrentIndex(index)
        self._endpoint_changed()

    def double_click(self, index):
        if index.column() == 0:
            self.toggle_favorite()
        elif index.column() == NAME:
            self.edit_label()
        elif self.selected() and self.selected().connectable:
            self.connect_remote()

    def table_context_menu(self, position):
        index = self.table.indexAt(position)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        device = self.selected()
        if not device:
            return
        menu = QMenu(self)
        connect = menu.addAction("Connect")
        connect.setEnabled(bool(device.connectable))
        connect.triggered.connect(self.connect_remote)
        advanced = menu.addAction("Advanced scan…")
        advanced.setToolTip("Read-only banner, access, risk, and fingerprint checks on this device.")
        advanced.triggered.connect(lambda _checked=False, address=device.address: self.start_advanced_scan(address))
        menu.addSeparator()
        label = menu.addAction("Edit label…")
        label.triggered.connect(self.edit_label)
        favorite = device.address in self.favorites
        favorite_action = menu.addAction("Remove favorite" if favorite else "Save favorite")
        favorite_action.triggered.connect(self.toggle_favorite)
        menu.exec(self.table.viewport().mapToGlobal(position))

    def toggle_favorite(self):
        device = self.selected()
        if not device:
            return
        if device.address in self.favorites:
            del self.favorites[device.address]
        else:
            self.favorites[device.address] = [
                favorite_ref(kind, service.port)
                for service in device.connectable
                if (kind := service_kind(service))
            ]
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

    def remote_client_settings(self) -> bool:
        dialog = RemoteClientsDialog(self.settings, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return False
        for kind, field in dialog.paths.items():
            text = field.text().strip()
            key = f"remote/{kind.lower()}_path"
            if text:
                self.settings.setValue(key, text)
            else:
                self.settings.remove(key)
            if kind == "VNC":
                self.settings.setValue("viewer/path", text)
        self.settings.setValue("viewer/style", dialog.style.currentText())
        self.settings.setValue("remote/ssh_user", dialog.ssh_user.text().strip())
        browser = dialog.browser.text().strip()
        if browser:
            self.settings.setValue("remote/browser_path", browser)
        else:
            self.settings.remove("remote/browser_path")
        return True

    def _endpoint_changed(self):
        selection = self.endpoint.currentData() or ""
        kind = selection.split(":", 1)[0] if selection else ""
        self.view_only.setEnabled(kind == "VNC")

    def connect_remote(self):
        device = self.selected()
        selection = self.endpoint.currentData()
        if not device or not selection:
            return
        kind, port_text = selection.split(":", 1)
        port = int(port_text)
        executable = _client_path(self.settings, kind)
        if kind == "VNC":
            executable = resolve_executable(executable)  # Accept a macOS .app bundle.
        if kind not in BROWSER_KINDS and (not executable or not Path(executable).is_file()):
            if not self.remote_client_settings():
                return
            executable = _client_path(self.settings, kind)
            if kind == "VNC":
                executable = resolve_executable(executable)
        try:
            launch_client(
                kind,
                executable,
                device.address,
                port,
                vnc_style=self.settings.value("viewer/style", "Double colon"),
                view_only=self.view_only.isChecked(),
                ssh_user=self.settings.value("remote/ssh_user", ""),
                browser_executable=self.settings.value("remote/browser_path", ""),
            )
            self.status.setText(f"Opened {kind} client for {device.address}:{port}")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not launch client", str(exc))

    def export_results(self):
        self.flush_updates()
        filename, _ = QFileDialog.getSaveFileName(self, "Export scan results", "connectinator-results.json", "JSON (*.json)")
        if not filename:
            return
        def export_entry(address, device):
            entry = dict(
                device.to_dict(),
                observed_this_scan=address in self.seen,
                favorite=address in self.favorites,
                connectable=[
                    favorite_ref(service_kind(s), s.port)
                    for s in device.connectable
                    if (service_kind(s))
                ],
            )
            if address in self.advanced_reports:
                entry["advanced_scan"] = self.advanced_reports[address].to_dict()
            return entry

        results = [
            export_entry(address, device)
            for address, device in sorted(self.devices.items(), key=lambda item: ipaddress.IPv4Address(item[0]))
        ]
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
        if self.worker is not None or self.availability_worker is not None or self.advanced_worker is not None:
            self.closing = True
            self.stop_scan()
            event.ignore()
        else:
            self.peer_discovery.stop()
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
    if sys.platform == "win32":
        app.setFont(QFont("Segoe UI", 10))  # Elsewhere keep the platform's native UI font.
    apply_theme(app)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
