import asyncio
import threading
import unittest
from unittest.mock import AsyncMock, patch

from connectinator.scanner import Service, parse_ports, parse_targets, ping_host, probe, scan


class ParsingTests(unittest.TestCase):
    def test_targets_deduplicate_sort_and_handle_small_subnets(self):
        self.assertEqual(parse_targets("192.168.1.2,192.168.1.0/30"), ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(parse_targets("10.0.0.0/31"), ["10.0.0.0", "10.0.0.1"])
        self.assertEqual(parse_targets("10.0.0.4-10.0.0.5"), ["10.0.0.4", "10.0.0.5"])

    def test_reject_invalid_and_excessive_targets(self):
        for value in ("", "::1", "example.com", "10.0.0.0/8", "10.0.0.9-10.0.0.1", "224.0.0.1", "0.0.0.0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_targets(value)

    def test_ports(self):
        self.assertEqual(parse_ports("22,5900-5902,22"), (22, 5900, 5901, 5902))
        for value in ("", "0", "65536", "1-65535", "80-22", "ssh"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []

    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()

    async def server(self, greeting: bytes, *, fragmented=False):
        async def handler(reader, writer):
            try:
                if fragmented:
                    writer.write(greeting[:5])
                    await writer.drain()
                    await asyncio.sleep(0.02)
                    writer.write(greeting[5:])
                else:
                    writer.write(greeting)
                await writer.drain()
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def test_fragmented_vnc_on_custom_port(self):
        port = await self.server(b"RFB 003.008\n", fragmented=True)
        service = await probe("127.0.0.1", port, 0.3)
        self.assertEqual((service.name, service.verified, service.banner), ("VNC", True, "RFB 003.008"))

    async def test_silent_and_non_vnc_servers_are_not_verified(self):
        for greeting in (b"", b"Not VNC !!!\n", b"RFB invalid\n"):
            port = await self.server(greeting)
            service = await probe("127.0.0.1", port, 0.05)
            self.assertFalse(service.verified)

    async def test_closed_port(self):
        port = await self.server(b"")
        self.servers[-1].close()
        await self.servers[-1].wait_closed()
        self.assertIsNone(await probe("127.0.0.1", port, 0.1))

    async def test_winrm_ports_are_not_vnc_candidates(self):
        local_port = await self.server(b"")
        real_connect = asyncio.open_connection

        async def connect_to_local_server(*_):
            return await real_connect("127.0.0.1", local_port)

        for port in (5985, 5986):
            with patch("connectinator.scanner.asyncio.open_connection",
                       side_effect=connect_to_local_server):
                service = await probe("127.0.0.1", port, 0.05)
            self.assertTrue(service.name.startswith("WinRM"))
            self.assertFalse(service.verified)

    async def test_scan_emits_result_and_progress(self):
        port = await self.server(b"RFB 003.008\n")
        devices, progress = [], []
        await scan(["127.0.0.1"], (port,), 0.2, threading.Event(), devices.append,
                   lambda done, total: progress.append((done, total)), use_ping=False)
        self.assertEqual(len(devices[0].vnc), 1)
        self.assertEqual(progress, [(1, 1)])

    async def test_vnc_is_published_before_slow_general_probes_and_ping(self):
        release = asyncio.Event()
        found = asyncio.Event()
        snapshots, order = [], []

        async def fake_probe(address, port, *args, **kwargs):
            order.append(port)
            if port == 5900:
                return Service(port, "VNC", True)
            await release.wait()
            return Service(port, "HTTP")

        async def fake_ping(*args):
            await release.wait()
            return True

        def receive(device):
            snapshots.append(device)
            if device.vnc:
                found.set()

        with patch("connectinator.scanner.probe", side_effect=fake_probe), \
             patch("connectinator.scanner.ping_host", side_effect=fake_ping):
            task = asyncio.create_task(scan(["127.0.0.1"], (80, 5900), 0.2,
                                           threading.Event(), receive, lambda *_: None))
            try:
                await asyncio.wait_for(found.wait(), 0.5)
                self.assertFalse(task.done())
                self.assertEqual(order[0], 5900)
                self.assertFalse(snapshots[0].complete)
                self.assertFalse(snapshots[0].ping)
            finally:
                release.set()
                await task
        self.assertEqual(len(snapshots[0].services), 1, "Published snapshots must not mutate")
        self.assertEqual(len(snapshots[-1].services), 2)
        self.assertTrue(snapshots[-1].ping)
        self.assertTrue(snapshots[-1].complete)

    async def test_connection_and_greeting_use_independent_timeouts(self):
        port = await self.server(b"RFB 003.008\n", fragmented=True)
        real_connect = asyncio.open_connection

        async def delayed_connect(*args):
            await asyncio.sleep(0.03)
            return await real_connect("127.0.0.1", port)

        with patch("connectinator.scanner.asyncio.open_connection", side_effect=delayed_connect):
            # A short connect budget cannot be rescued by a generous greeting budget.
            self.assertIsNone(await probe("127.0.0.1", port, 0.005, 0.5))
            service = await probe("127.0.0.1", port, 0.3, 0.3)
            self.assertTrue(service.verified)

    async def test_short_greeting_budget_keeps_open_port_unverified(self):
        port = await self.server(b"RFB 003.008\n", fragmented=True)
        service = await probe("127.0.0.1", port, 0.5, 0.005)
        self.assertIsNotNone(service)
        self.assertFalse(service.verified)

    async def test_common_profile_shortens_client_first_greetings(self):
        port = await self.server(b"")
        real_connect = asyncio.open_connection

        async def connect_local(*args):
            return await real_connect("127.0.0.1", port)

        real_wait = asyncio.wait_for
        budgets = []

        async def record_budget(awaitable, timeout):
            budgets.append(timeout)
            return await real_wait(awaitable, timeout)

        with patch("connectinator.scanner.asyncio.open_connection", side_effect=connect_local), \
             patch("connectinator.scanner.asyncio.wait_for", side_effect=record_budget):
            await probe("127.0.0.1", 80, 0.4, 0.5, quick_greetings=True)
        self.assertEqual(budgets[:2], [0.4, 0.1])

    async def test_arp_can_discover_device_without_ping_or_open_tcp(self):
        devices = []

        async def fake_arp(targets, on_device, on_warning):
            on_device("10.0.0.2", "AA:BB:CC:DD:EE:FF")

        with patch("connectinator.scanner.probe", new_callable=AsyncMock, return_value=None), \
             patch("connectinator.discovery.discover_arp", side_effect=fake_arp):
            await scan(["10.0.0.2"], (5900,), 0.1, threading.Event(), devices.append,
                       lambda *_: None, use_ping=False, arp_targets={"10.0.0.2": "10.0.0.1"})
        self.assertEqual(devices[-1].mac, "AA:BB:CC:DD:EE:FF")
        self.assertFalse(devices[-1].ping)
        self.assertFalse(devices[-1].services)
        self.assertTrue(devices[-1].complete)

    async def test_cancel_interrupts_active_socket_read(self):
        port = await self.server(b"")
        cancel = threading.Event()
        asyncio.get_running_loop().call_later(0.03, cancel.set)
        devices = []
        await asyncio.wait_for(scan(["127.0.0.1"], (port,), 5.0, cancel,
                                   devices.append, lambda *_: None, use_ping=False), 0.8)
        self.assertFalse(devices)

    async def test_pre_cancelled_scan_does_no_work(self):
        cancel = threading.Event()
        cancel.set()
        with patch("connectinator.scanner.probe", new_callable=AsyncMock) as mocked:
            await scan(["127.0.0.1"], (5900,), 0.1, cancel, lambda _: None, lambda *_: None)
            mocked.assert_not_awaited()

    async def test_windows_unreachable_is_not_a_discovered_host(self):
        process = AsyncMock()
        process.returncode = 0
        process.communicate.return_value = (b"Reply from 10.0.0.1: Destination host unreachable.", b"")
        with patch("connectinator.scanner.sys.platform", "win32"), \
             patch("connectinator.scanner.shutil.which", return_value="ping.exe"), \
             patch("connectinator.scanner.asyncio.create_subprocess_exec", return_value=process):
            self.assertFalse(await ping_host("10.0.0.2", 0.2))
