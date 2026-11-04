import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import time
import unittest
from unittest.mock import patch

from PySide6.QtNetwork import QHostInfo
from PySide6.QtWidgets import QApplication

from connectinator.names import HostnameResolver


class HostnameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.resolver = HostnameResolver()

    def tearDown(self):
        self.resolver.cancel()
        self.resolver.deleteLater()

    def info(self, lookup_id, hostname):
        info = QHostInfo(lookup_id)
        info.setHostName(hostname)
        info.setError(QHostInfo.HostInfoError.NoError)
        return info

    def test_bounded_queue_and_cached_success(self):
        results = []
        self.resolver.resolved.connect(lambda *args: results.append(args))
        with patch("connectinator.names.QHostInfo.lookupHost", side_effect=range(1, 30)) as lookup, \
             patch("connectinator.names.QHostInfo.abortHostLookup"):
            for index in range(1, 13):
                self.resolver.lookup(f"10.0.0.{index}")
            self.assertEqual(len(self.resolver.active), 8)
            self.assertEqual(len(self.resolver.pending), 4)
            self.resolver.receive(self.info(1, "shop-pc"))
            self.assertEqual(results, [("10.0.0.1", "shop-pc")])
            self.assertEqual(len(self.resolver.active), 8)
            self.resolver.cancel()
            calls = lookup.call_count
            self.resolver.lookup("10.0.0.1")
            self.assertEqual(lookup.call_count, calls)
            self.assertEqual(results[-1], ("10.0.0.1", "shop-pc"))

    def test_cancel_and_timeout_ignore_late_callbacks(self):
        results = []
        self.resolver.resolved.connect(lambda *args: results.append(args))
        with patch("connectinator.names.QHostInfo.lookupHost", side_effect=[10, 11]), \
             patch("connectinator.names.QHostInfo.abortHostLookup") as abort:
            self.resolver.lookup("10.0.0.1")
            self.resolver.cancel()
            self.resolver.receive(self.info(10, "old-name"))
            self.resolver.lookup("10.0.0.2")
            self.resolver.active[11] = ("10.0.0.2", time.monotonic() - 1)
            self.resolver.pump()
            self.resolver.receive(self.info(11, "late-name"))
            self.assertFalse(results)
            self.assertFalse(self.resolver.active)
            self.assertFalse(self.resolver.timer.isActive())
            self.assertEqual(abort.call_count, 2)
