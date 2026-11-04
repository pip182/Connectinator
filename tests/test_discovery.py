import asyncio
import ctypes
import json
import socket
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from connectinator.discovery import _send_arp, arp_targets_for, discover_arp


class ArpScopeTests(unittest.TestCase):
    def test_only_on_link_unicast_targets_and_longest_prefix(self):
        interfaces = [("10.0.0.1", 24), ("10.0.0.129", 25), ("100.64.0.1", 32), ("127.0.0.1", 8)]
        targets = ["10.0.0.2", "10.0.0.130", "10.0.0.255", "10.0.0.0", "10.0.0.1",
                   "10.0.0.129", "10.1.0.2", "100.64.0.2", "127.0.0.2", "224.0.0.1"]
        self.assertEqual(arp_targets_for(targets, interfaces),
                         {"10.0.0.2": "10.0.0.1", "10.0.0.130": "10.0.0.129"})

    def test_native_buffer_and_network_byte_order(self):
        class Send:
            def __call__(inner, destination, source, buffer, length):
                self.assertEqual(socket.inet_ntoa(destination.to_bytes(4, sys.byteorder)), "10.0.0.2")
                self.assertEqual(socket.inet_ntoa(source.to_bytes(4, sys.byteorder)), "10.0.0.1")
                ctypes.memmove(buffer, bytes.fromhex("AABBCCDDEEFF"), 6)
                ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32))[0] = 6
                return 0

        dll = MagicMock()
        dll.SendARP = Send()
        with patch("connectinator.discovery.ctypes.WinDLL", return_value=dll, create=True):
            self.assertEqual(_send_arp("10.0.0.2", "10.0.0.1"), "AA:BB:CC:DD:EE:FF")


class ArpProcessTests(unittest.IsolatedAsyncioTestCase):
    def process(self):
        process = MagicMock()
        process.stdin.drain = AsyncMock()
        process.stdout.readline = AsyncMock()
        process.wait = AsyncMock(return_value=0)
        process.returncode = 0
        return process

    async def test_streams_live_results_without_cached_neighbors(self):
        process = self.process()
        process.stdout.readline.side_effect = [
            (json.dumps({"address": "10.0.0.2", "mac": "AA:BB:CC:DD:EE:FF"}) + "\n").encode(), b"",
        ]
        found, warnings = [], []
        with patch("connectinator.discovery.sys.platform", "win32"), \
             patch("connectinator.discovery.asyncio.create_subprocess_exec", return_value=process) as spawn:
            await discover_arp({"10.0.0.2": "10.0.0.1"}, lambda *args: found.append(args), warnings.append)
        self.assertEqual(found, [("10.0.0.2", "AA:BB:CC:DD:EE:FF")])
        self.assertFalse(warnings)
        self.assertNotIn("shell", spawn.call_args.kwargs)
        process.kill.assert_not_called()

    async def test_cancellation_terminates_the_native_helper(self):
        process = self.process()
        process.returncode = None
        reading = asyncio.Event()

        async def blocked_read():
            reading.set()
            await asyncio.Event().wait()

        process.stdout.readline.side_effect = blocked_read
        with patch("connectinator.discovery.sys.platform", "win32"), \
             patch("connectinator.discovery.asyncio.create_subprocess_exec", return_value=process):
            task = asyncio.create_task(discover_arp({"10.0.0.2": "10.0.0.1"}, lambda *_: None, lambda _: None))
            await asyncio.wait_for(reading.wait(), 0.5)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        process.kill.assert_called_once()
        process.wait.assert_awaited_once()

    async def test_helper_failure_is_nonfatal_and_reported(self):
        warnings = []
        with patch("connectinator.discovery.sys.platform", "win32"), \
             patch("connectinator.discovery.asyncio.create_subprocess_exec", side_effect=OSError):
            await discover_arp({"10.0.0.2": "10.0.0.1"}, lambda *_: None, warnings.append)
        self.assertIn("unavailable", warnings[0])
