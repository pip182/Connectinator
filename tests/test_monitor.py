import asyncio
import threading
import unittest
from unittest.mock import AsyncMock, patch

from connectinator.monitor import check_devices, tcp_open
from connectinator.scanner import Device, Service


class MonitorTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_loopback_connection_without_waiting_for_greeting(self):
        async def handler(reader, writer):
            try:
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        try:
            self.assertTrue(await tcp_open("127.0.0.1", server.sockets[0].getsockname()[1], 0.2))
        finally:
            server.close()
            await server.wait_closed()

    async def test_vnc_port_is_auto_verified_by_rfb_greeting(self):
        async def rfb(reader, writer):
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            writer.close()

        async def silent(reader, writer):
            try:
                await reader.read()
            finally:
                writer.close()

        real = await asyncio.start_server(rfb, "127.0.0.1", 0)
        fake = await asyncio.start_server(silent, "127.0.0.1", 0)
        try:
            real_port = real.sockets[0].getsockname()[1]
            fake_port = fake.sockets[0].getsockname()[1]
            results = []
            await check_devices([Device("127.0.0.1", [Service(real_port, "VNC"), Service(fake_port, "VNC")])],
                                0.3, threading.Event(), results.append)
        finally:
            real.close()
            fake.close()
        self.assertEqual(results[0].verified_vnc, (real_port,))
        self.assertEqual(set(results[0].probed_vnc), {real_port, fake_port})

    async def test_online_via_known_port_skips_ping_and_limits_probes(self):
        devices = [Device("10.0.0.2", [Service(p, "VNC" if p == 5907 else "TCP") for p in (22, 80, 443, 445, 5907)])]
        results = []
        with patch("connectinator.monitor.tcp_open", new_callable=AsyncMock, return_value=True) as tcp, \
             patch("connectinator.monitor.probe", new_callable=AsyncMock, return_value=Service(5907, "VNC")) as vnc, \
             patch("connectinator.monitor.ping_host", new_callable=AsyncMock) as ping:
            await check_devices(devices, 0.1, threading.Event(), results.append)
        self.assertEqual(tcp.await_count + vnc.await_count, 3)
        self.assertEqual(vnc.await_args_list[0].args[1], 5907)
        ping.assert_not_awaited()
        self.assertTrue(results[0].online)
        self.assertEqual(results[0].evidence, "TCP")

    async def test_ping_fallback_and_offline_results(self):
        results = []
        with patch("connectinator.monitor.ping_host", new_callable=AsyncMock, side_effect=[True, False]):
            await check_devices([Device("10.0.0.2"), Device("10.0.0.3")], 0.1, threading.Event(), results.append)
        self.assertEqual({r.address: r.online for r in results}, {"10.0.0.2": True, "10.0.0.3": False})

    async def test_arp_fallback_does_not_publish_false_offline_first(self):
        results = []

        async def fake_arp(targets, on_device, warning):
            on_device("10.0.0.2", "AA:BB:CC:DD:EE:FF")

        with patch("connectinator.monitor.discover_arp", side_effect=fake_arp):
            await check_devices([Device("10.0.0.2")], 0.1, threading.Event(), results.append,
                                use_ping=False, arp_targets={"10.0.0.2": "10.0.0.1"})
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].online)
        self.assertEqual(results[0].mac, "AA:BB:CC:DD:EE:FF")

    async def test_cancel_does_not_mark_unchecked_devices_offline(self):
        started, release = asyncio.Event(), asyncio.Event()
        cancel = threading.Event()
        results = []

        async def blocked(*args):
            started.set()
            await release.wait()

        with patch("connectinator.monitor.probe", side_effect=blocked):
            task = asyncio.create_task(check_devices([Device("10.0.0.2", [Service(5900, "VNC")])],
                                                    5, cancel, results.append))
            await asyncio.wait_for(started.wait(), 0.5)
            cancel.set()
            await asyncio.wait_for(task, 0.5)
        self.assertFalse(results)
