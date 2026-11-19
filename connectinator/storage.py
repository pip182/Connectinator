"""Transactional per-user inventory. Reachability is always unchecked on reload."""

from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sqlite3

from .scanner import Device, Service


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class InventoryStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, timeout=0.2)
        try:
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("CREATE TABLE IF NOT EXISTS devices (address TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            self.connection.commit()
        except Exception:
            self.connection.close()
            raise

    def load(self) -> list[Device]:
        devices = []
        for address, payload in self.connection.execute("SELECT address, payload FROM devices ORDER BY address"):
            try:
                address = str(ipaddress.IPv4Address(address))
                data = json.loads(payload)
                services = [Service(int(s["port"]), str(s["name"]), False,
                                    str(s.get("banner", "")), str(s.get("source", "")))
                            for s in data.get("services", []) if 1 <= int(s["port"]) <= 65535]
                devices.append(Device(address, services, hostname=str(data.get("hostname", "")),
                                      label=str(data.get("label", "")), mac=str(data.get("mac", "")),
                                      complete=bool(data.get("complete", True)),
                                      last_seen=str(data.get("last_seen", "")),
                                      last_checked=str(data.get("last_checked", ""))))
            except (ValueError, TypeError, KeyError, AttributeError):
                continue  # One malformed row must not prevent loading other devices.
        return devices

    def save(self, devices: list[Device]):
        with self.connection:
            self.connection.executemany(
                "INSERT INTO devices(address, payload) VALUES (?, ?) "
                "ON CONFLICT(address) DO UPDATE SET payload=excluded.payload",
                [(device.address, json.dumps(device.to_dict())) for device in devices],
            )

    def close(self):
        self.connection.close()
