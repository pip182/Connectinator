from pathlib import Path
import tempfile
import unittest

from connectinator.scanner import Device, Service
from connectinator.storage import InventoryStore


class StorageTests(unittest.TestCase):
    def test_reload_preserves_inventory_but_does_not_claim_device_is_online(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.sqlite3"
            store = InventoryStore(path)
            store.save([Device("10.0.0.2", [Service(5907, "VNC", True, "RFB 003.008")],
                               hostname="shop-pc", label="Shop", mac="AA:BB:CC:DD:EE:FF", online=True,
                               last_seen="2026-11-04T12:00:00+00:00", last_checked="2026-11-04T12:00:00+00:00")])
            store.close()
            reopened = InventoryStore(path)
            try:
                device = reopened.load()[0]
                self.assertIsNone(device.online)
                self.assertFalse(device.vnc)
                self.assertEqual(device.candidates[0].port, 5907)
                self.assertEqual((device.hostname, device.label, device.mac), ("shop-pc", "Shop", "AA:BB:CC:DD:EE:FF"))
                self.assertEqual(device.last_seen, "2026-11-04T12:00:00+00:00")
            finally:
                reopened.close()

    def test_upserts_and_skips_malformed_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            store = InventoryStore(Path(directory) / "devices.sqlite3")
            try:
                store.save([Device("10.0.0.2", hostname="old")])
                store.save([Device("10.0.0.2", hostname="new")])
                with store.connection:
                    store.connection.execute("INSERT INTO devices VALUES (?, ?)", ("10.0.0.3", "broken json"))
                loaded = store.load()
                self.assertEqual(len(loaded), 1)
                self.assertEqual(loaded[0].hostname, "new")
            finally:
                store.close()
