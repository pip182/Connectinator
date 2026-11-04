"""Bounded async Qt reverse DNS, with TTL caching and cancellation."""

from collections import deque
import time

from PySide6.QtCore import QObject, QTimer, Signal, Slot, SLOT
from PySide6.QtNetwork import QHostInfo


class HostnameResolver(QObject):
    resolved = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cache: dict[str, tuple[float, str]] = {}
        self.pending = deque()
        self.requested: set[str] = set()
        self.active: dict[int, tuple[str, float]] = {}
        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self.pump)

    def lookup(self, address: str):
        if address in self.requested:
            return
        self.requested.add(address)
        cached = self.cache.get(address)
        if cached and cached[0] > time.monotonic():
            if cached[1]:
                self.resolved.emit(address, cached[1])
            return
        self.pending.append(address)
        self.pump()

    @Slot()
    def pump(self):
        now = time.monotonic()
        for lookup_id, (address, deadline) in list(self.active.items()):
            if now >= deadline:
                QHostInfo.abortHostLookup(lookup_id)
                del self.active[lookup_id]
                self.cache[address] = (now + 30, "")
        while self.pending and len(self.active) < 8:
            address = self.pending.popleft()
            lookup_id = QHostInfo.lookupHost(address, self, SLOT("receive(QHostInfo)"))
            self.active[lookup_id] = (address, now + 2)
        if self.active or self.pending:
            if not self.timer.isActive():
                self.timer.start()
        else:
            self.timer.stop()

    @Slot(QHostInfo)
    def receive(self, info):
        job = self.active.pop(info.lookupId(), None)
        if job is None:
            return  # Aborted/timed-out/previous-scan results cannot update the UI.
        address = job[0]
        name = info.hostName().rstrip(".") if info.error() == QHostInfo.HostInfoError.NoError else ""
        if name == address:
            name = ""
        self.cache[address] = (time.monotonic() + (300 if name else 30), name)
        if name:
            self.resolved.emit(address, name)
        self.pump()

    def cancel(self):
        self.timer.stop()
        for lookup_id in self.active:
            QHostInfo.abortHostLookup(lookup_id)
        self.active.clear()
        self.pending.clear()
        self.requested.clear()
