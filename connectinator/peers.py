"""Find other running Connectinator instances on the local network.

Each instance broadcasts a small JSON beacon over UDP and replies directly to a
newcomer's "hello" so peers appear within a second of starting. QUdpSocket is
event-driven, so reading these tiny datagrams never blocks the GUI thread.
Datagrams are untrusted: they are size-limited, strictly validated, and the
peer's address always comes from the datagram sender, never from its payload.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import time
import uuid

from PySide6.QtCore import QObject, QSysInfo, QTimer, Signal, Slot
from PySide6.QtNetwork import QAbstractSocket, QHostAddress, QNetworkInterface, QUdpSocket

PORT = 47823
MAGIC = "connectinator-peer"
VERSION = 1
ANNOUNCE_MS = 5000
EXPIRY_S = 17.0          # three missed beacons
REFRESH_S = 60.0
MAX_DATAGRAM = 1024
MAX_PEERS = 256
MAX_READS_PER_EVENT = 64
KINDS = ("hello", "announce", "bye")


@dataclass(frozen=True)
class Peer:
    address: str
    instance: str
    name: str
    platform: str
    version: str = ""


def encode(kind: str, instance: str, name: str, platform: str, version: str = "") -> bytes:
    payload = {"magic": MAGIC, "v": VERSION, "kind": kind, "id": instance,
               "name": name[:64], "platform": platform[:64], "app": version[:16]}
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def decode(data: bytes) -> dict | None:
    """Return a validated message, or None for anything that isn't a peer beacon."""
    if not data or len(data) > MAX_DATAGRAM:
        return None
    try:
        message = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(message, dict) or message.get("magic") != MAGIC or message.get("v") != VERSION:
        return None
    kind, instance = message.get("kind"), message.get("id")
    if kind not in KINDS or not isinstance(instance, str) or not 8 <= len(instance) <= 64:
        return None
    fields = {}
    for key in ("name", "platform", "app"):
        value = message.get(key, "")
        # Keep only printable text; names are displayed in the device table.
        fields[key] = "".join(ch for ch in value if ch.isprintable())[:64] if isinstance(value, str) else ""
    return {"kind": kind, "id": instance, **fields}


def broadcast_addresses() -> list[str]:
    """Directed broadcast for each up IPv4 interface, plus the limited broadcast."""
    found = []
    for interface in QNetworkInterface.allInterfaces():
        flags = interface.flags()
        if (not flags & QNetworkInterface.InterfaceFlag.IsUp
                or not flags & QNetworkInterface.InterfaceFlag.CanBroadcast
                or flags & QNetworkInterface.InterfaceFlag.IsLoopBack):
            continue
        for entry in interface.addressEntries():
            broadcast = entry.broadcast()
            if (entry.ip().protocol() == QAbstractSocket.NetworkLayerProtocol.IPv4Protocol
                    and not broadcast.isNull()):
                found.append(broadcast.toString())
    found.append("255.255.255.255")
    return list(dict.fromkeys(found))


class PeerDiscovery(QObject):
    peer_seen = Signal(object)   # Peer
    peer_lost = Signal(str)      # IPv4 address
    failed = Signal(str)

    def __init__(self, parent=None, *, port: int = PORT, targets=None, name: str = "",
                 version: str = ""):
        """targets: optional [(address, port)] used instead of LAN broadcasts (tests)."""
        super().__init__(parent)
        self.port, self.targets = port, targets
        self.instance = uuid.uuid4().hex
        self.name = name or QSysInfo.machineHostName() or "Unknown computer"
        self.platform = QSysInfo.prettyProductName() or QSysInfo.productType()
        self.version = version
        self.socket: QUdpSocket | None = None
        self.peers: dict[str, tuple[Peer, float, float]] = {}  # peer, seen, emitted
        self.replied: dict[str, float] = {}
        self.timer = QTimer(self)
        self.timer.setInterval(ANNOUNCE_MS)
        self.timer.timeout.connect(self.tick)

    @property
    def running(self) -> bool:
        return self.socket is not None

    def start(self) -> bool:
        if self.socket is not None:
            return True
        socket = QUdpSocket(self)
        mode = (QAbstractSocket.BindFlag.ShareAddress | QAbstractSocket.BindFlag.ReuseAddressHint)
        if not socket.bind(QHostAddress(QHostAddress.SpecialAddress.AnyIPv4), self.port, mode):
            error = socket.errorString()
            socket.deleteLater()
            self.failed.emit(f"Peer discovery unavailable on UDP {self.port}: {error}")
            return False
        socket.readyRead.connect(self.read)
        self.socket = socket
        self.send("hello")
        self.timer.start()
        return True

    def stop(self):
        self.timer.stop()
        socket, self.socket = self.socket, None
        if socket is None:
            return
        self._send_with(socket, "bye")
        socket.close()
        socket.deleteLater()
        lost, self.peers = list(self.peers), {}
        self.replied.clear()
        for address in lost:
            self.peer_lost.emit(address)

    def destinations(self) -> list[tuple[str, int]]:
        return list(self.targets) if self.targets is not None else [(a, self.port) for a in broadcast_addresses()]

    def send(self, kind: str, destination: tuple[str, int] | None = None):
        if self.socket is not None:
            self._send_with(self.socket, kind, destination)

    def _send_with(self, socket: QUdpSocket, kind: str, destination=None):
        data = encode(kind, self.instance, self.name, self.platform, self.version)
        for address, port in [destination] if destination else self.destinations():
            # Errors (no route, interface down) are expected on some adapters; the next beacon retries.
            socket.writeDatagram(data, QHostAddress(address), port)

    @Slot()
    def tick(self):
        self.send("announce")
        now = time.monotonic()
        for address, (_, seen, _) in list(self.peers.items()):
            if now - seen > EXPIRY_S:
                del self.peers[address]
                self.peer_lost.emit(address)
        self.replied = {a: t for a, t in self.replied.items() if now - t < 2}

    @Slot()
    def read(self):
        socket = self.socket
        if socket is None:
            return
        for _ in range(MAX_READS_PER_EVENT):
            if not socket.hasPendingDatagrams():
                return
            size = socket.pendingDatagramSize()
            data, sender, sender_port = socket.readDatagram(max(1, min(size, MAX_DATAGRAM + 1)))
            self.receive(bytes(data), sender, sender_port)
        QTimer.singleShot(0, self.read)  # Yield to the event loop during a burst.

    def receive(self, data: bytes, sender: QHostAddress, sender_port: int):
        message = decode(data)
        if message is None or message["id"] == self.instance:
            return
        try:
            ip = ipaddress.ip_address(sender.toString().split("%")[0])
        except ValueError:
            return
        ip = getattr(ip, "ipv4_mapped", None) or ip
        if ip.version != 4:
            return
        address = str(ip)
        if message["kind"] == "bye":
            current = self.peers.get(address)
            if current and current[0].instance == message["id"]:
                del self.peers[address]
                self.peer_lost.emit(address)
            return
        if address not in self.peers and len(self.peers) >= MAX_PEERS:
            return
        now = time.monotonic()
        peer = Peer(address, message["id"], message["name"] or address, message["platform"], message["app"])
        previous = self.peers.get(address)
        # Re-emit unchanged peers once a minute to refresh "last seen" without churn.
        if previous is None or previous[0] != peer or now - previous[2] >= REFRESH_S:
            self.peers[address] = (peer, now, now)
            self.peer_seen.emit(peer)
        else:
            self.peers[address] = (peer, now, previous[2])
        if message["kind"] == "hello" and now - self.replied.get(address, -10) >= 1:
            # Answer newcomers directly so they don't wait for the next beacon.
            self.replied[address] = now
            self.send("announce", (address, sender_port))
