import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import socket
import time
import unittest

from PySide6.QtCore import QCoreApplication
from PySide6.QtNetwork import QHostAddress

from connectinator import peers
from connectinator.peers import Peer, PeerDiscovery, decode, encode


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class CodecTests(unittest.TestCase):
    def test_round_trip_and_rejects_foreign_or_malformed_data(self):
        message = decode(encode("hello", "a" * 32, "Shop PC", "Windows 11", "0.1"))
        self.assertEqual(message, {"kind": "hello", "id": "a" * 32, "name": "Shop PC",
                                   "platform": "Windows 11", "app": "0.1"})
        for data in (b"", b"\xff\xfe", b"[]", b'{"magic":"other","v":1}', b"x" * 2000,
                     b'{"magic":"connectinator-peer","v":1,"kind":"rm","id":"aaaaaaaa"}',
                     b'{"magic":"connectinator-peer","v":1,"kind":"hello","id":"short"}',
                     b'{"magic":"connectinator-peer","v":2,"kind":"hello","id":"aaaaaaaa"}'):
            self.assertIsNone(decode(data), data)

    def test_untrusted_text_is_cleaned_and_bounded(self):
        data = b'{"magic":"connectinator-peer","v":1,"kind":"announce","id":"abcdefgh",' \
               b'"name":"evil\\nname\\u0000' + b"x" * 200 + b'","platform":42}'
        message = decode(data)
        self.assertEqual(message["name"], "evilname" + "x" * 56)
        self.assertEqual(message["platform"], "")


class LoopbackDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def wait_for(self, condition, timeout=3):
        deadline = time.monotonic() + timeout
        while not condition() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.01)
        return condition()

    def test_instances_find_each_other_and_say_goodbye(self):
        port_a, port_b = free_udp_port(), free_udp_port()
        a = PeerDiscovery(port=port_a, targets=[("127.0.0.1", port_b)], name="alpha")
        b = PeerDiscovery(port=port_b, targets=[("127.0.0.1", port_a)], name="bravo")
        seen_a, seen_b, lost_a = [], [], []
        a.peer_seen.connect(seen_a.append)
        b.peer_seen.connect(seen_b.append)
        a.peer_lost.connect(lost_a.append)
        try:
            self.assertTrue(a.start())
            # A's hello reaches nobody yet; B's hello is answered directly by A.
            self.assertTrue(b.start())
            self.assertTrue(self.wait_for(lambda: seen_a and seen_b))
            self.assertEqual((seen_a[0].address, seen_a[0].name), ("127.0.0.1", "bravo"))
            self.assertEqual(seen_b[0].name, "alpha")
            b.stop()
            self.assertTrue(self.wait_for(lambda: lost_a == ["127.0.0.1"]))
            self.assertEqual(a.peers, {})
        finally:
            a.stop()
            b.stop()

    def test_ignores_own_beacons_and_expires_silent_peers(self):
        port = free_udp_port()
        node = PeerDiscovery(port=port, targets=[("127.0.0.1", port)], name="self")
        seen, lost = [], []
        node.peer_seen.connect(seen.append)
        node.peer_lost.connect(lost.append)
        try:
            self.assertTrue(node.start())
            self.wait_for(lambda: False, 0.2)
            self.assertEqual(seen, [])  # Its own looped-back hello is ignored.
            node.receive(encode("announce", "b" * 32, "other", "Linux"), QHostAddress("10.0.0.7"), port)
            self.assertEqual([p.address for p in seen], ["10.0.0.7"])
            node.receive(encode("announce", "b" * 32, "other", "Linux"), QHostAddress("10.0.0.7"), port)
            self.assertEqual(len(seen), 1)  # Unchanged beacons don't re-emit immediately.
            peer, _, emitted = node.peers["10.0.0.7"]
            node.peers["10.0.0.7"] = (peer, time.monotonic() - peers.EXPIRY_S - 1, emitted)
            node.tick()
            self.assertEqual(lost, ["10.0.0.7"])
            # A goodbye from a different instance at the same address is ignored.
            node.receive(encode("announce", "b" * 32, "other", "Linux"), QHostAddress("10.0.0.7"), port)
            node.receive(encode("bye", "c" * 32, "x", ""), QHostAddress("10.0.0.7"), port)
            self.assertIn("10.0.0.7", node.peers)
        finally:
            node.stop()

    def test_bind_failure_is_reported(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
            holder.bind(("0.0.0.0", 0))  # Exclusive (no SO_REUSEADDR).
            node = PeerDiscovery(port=holder.getsockname()[1], targets=[])
            errors = []
            node.failed.connect(errors.append)
            started = node.start()
            node.stop()
        if started:
            self.skipTest("Platform allowed sharing an exclusively bound UDP port")
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
