"""Table model with cached row presentation and one proxy refresh per update batch."""

from dataclasses import replace
import ipaddress

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from .scanner import Device
from .icons import icon

STAR, ADDRESS, NAME, MAC, DISCOVERY, VNC, SERVICES = range(7)
HEADERS = ("", "IP address", "Name / label", "MAC address", "Discovery", "VNC", "Open TCP services")


class DeviceModel(QAbstractTableModel):
    def __init__(self, favorites: dict, labels: dict, parent=None):
        super().__init__(parent)
        self.favorites, self.labels = favorites, labels
        self.devices: dict[str, Device] = {}
        self.seen: set[str] = set()
        self.addresses: list[str] = []
        self.rows: dict[str, int] = {}
        self.cells: dict[str, tuple[str, ...]] = {}
        self.search_text: dict[str, str] = {}
        self.numeric_addresses: dict[str, int] = {}
        self.confirmed = 0
        self.scanning = False

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.addresses)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if section == STAR and orientation == Qt.Orientation.Horizontal:
            if role == Qt.ItemDataRole.DecorationRole:
                return icon("star", "#f2ce75")
            if role == Qt.ItemDataRole.ToolTipRole:
                return "Favorites"
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        address = self.addresses[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return self.cells[address][index.column()]
        if role == Qt.ItemDataRole.UserRole:
            return address
        device = self.devices[address]
        if role == Qt.ItemDataRole.DecorationRole:
            if index.column() == STAR and address in self.favorites:
                return icon("star", "#f2ce75")
            if index.column() == NAME and (device.label or device.hostname):
                return icon("tag" if device.label else "desktop")
            if index.column() == VNC:
                if device.vnc:
                    return icon("circle-check", "#58dfb3")
                if device.candidates:
                    return icon("circle-question", "#f2ce75")
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == VNC and device.vnc:
            return QColor("#58dfb3")
        if role == Qt.ItemDataRole.ToolTipRole:
            return "\n".join(v for v in (address, device.label, device.hostname, device.mac) if v)
        return None

    def clear(self):
        self.beginResetModel()
        self.devices.clear()
        self.seen.clear()
        self.addresses.clear()
        self.rows.clear()
        self.cells.clear()
        self.search_text.clear()
        self.numeric_addresses.clear()
        self.confirmed = 0
        self.endResetModel()

    def _cache_row(self, device: Device):
        address = device.address
        verified = ", ".join(str(s.port) for s in device.vnc)
        candidates = ", ".join(str(s.port) for s in device.candidates if not s.verified)
        vnc = f"Verified · {verified}" if verified else f"Unverified · {candidates}" if candidates else "—"
        evidence = [name for present, name in ((device.services, "TCP"), (device.ping, "ping"), (device.mac, "ARP")) if present]
        discovery = " + ".join(evidence) if address in self.seen else "Saved · unchecked"
        if address in self.seen and not device.complete:
            discovery += " · scanning" if self.scanning else " · partial"
        services = ", ".join(f"{s.name}:{s.port}{' ✓' if s.verified else ''}" for s in device.services)
        self.cells[address] = (
            "", address,
            device.label or device.hostname or "—", device.mac or "—", discovery, vnc,
            services or ("Checking ports…" if not device.complete else "No open scanned ports"),
        )
        self.search_text[address] = " ".join((*self.cells[address], device.hostname, device.label)).casefold()

    def apply(self, devices: list[Device], *, observed=True):
        if not devices:
            return
        updates = {device.address: device for device in devices}
        added = [address for address in updates if address not in self.rows]
        added_set = set(added)
        if added:
            first = len(self.addresses)
            self.beginInsertRows(QModelIndex(), first, first + len(added) - 1)
            for address in added:
                self.rows[address] = len(self.addresses)
                self.addresses.append(address)
                self.numeric_addresses[address] = int(ipaddress.IPv4Address(address))
            # Populate data before endInsertRows, when the view/proxy can read it.
        changed = []
        for address, device in updates.items():
            old = self.devices.get(address)
            was_confirmed = bool(old and old.vnc and address in self.seen)
            if observed:
                self.seen.add(address)
            device = replace(device, hostname=device.hostname or (old.hostname if old else ""),
                             label=self.labels.get(address, ""))
            self.devices[address] = device
            self.confirmed += int(bool(device.vnc) and address in self.seen) - int(was_confirmed)
            self._cache_row(device)
            if address not in added_set:
                changed.append(self.rows[address])
        if added:
            self.endInsertRows()
        if changed:
            self.dataChanged.emit(self.index(min(changed), 0), self.index(max(changed), len(HEADERS) - 1))

    def refresh(self, address: str):
        if address not in self.rows:
            return
        self.devices[address] = replace(self.devices[address], label=self.labels.get(address, ""))
        self._cache_row(self.devices[address])
        row = self.rows[address]
        self.dataChanged.emit(self.index(row, 0), self.index(row, len(HEADERS) - 1))


class DeviceFilter(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.query, self.only_vnc, self.only_favorites = "", False, False
        self.setDynamicSortFilter(False)

    def set_filters(self, query: str, only_vnc: bool, only_favorites: bool):
        self.query = query.strip().casefold()
        self.only_vnc, self.only_favorites = only_vnc, only_favorites
        self.invalidate()

    def filterAcceptsRow(self, row, parent):
        model = self.sourceModel()
        address = model.addresses[row]
        return (self.query in model.search_text[address]
                and (not self.only_vnc or bool(model.devices[address].candidates))
                and (not self.only_favorites or address in model.favorites))

    def lessThan(self, left, right):
        model = self.sourceModel()
        left_address, right_address = model.addresses[left.row()], model.addresses[right.row()]
        if left.column() == STAR:
            return (left_address in model.favorites) < (right_address in model.favorites)
        if left.column() == ADDRESS:
            return model.numeric_addresses[left_address] < model.numeric_addresses[right_address]
        return model.cells[left_address][left.column()].casefold() < model.cells[right_address][right.column()].casefold()
