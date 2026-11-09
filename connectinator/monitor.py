"""Cancellable checks of known devices, without repeating a full service scan."""

import asyncio
from dataclasses import dataclass
import threading

from .discovery import discover_arp
from .scanner import Device, ping_host, probe
from .storage import utc_now


@dataclass(frozen=True)
class Availability:
    address: str
    online: bool
    checked_at: str
    evidence: str = ""
    mac: str = ""
    probed_vnc: tuple[int, ...] = ()    # VNC ports that answered the TCP connection
    verified_vnc: tuple[int, ...] = ()  # subset that sent an RFB greeting


async def tcp_open(address: str, port: int, timeout: float) -> bool:
    writer = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
        return True
    except (OSError, TimeoutError):
        return False
    finally:
        if writer:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.2)
            except (OSError, TimeoutError):
                pass


async def check_devices(devices: list[Device], timeout: float, cancel: threading.Event,
                        on_result, *, use_ping=True, arp_targets=None, on_warning=lambda _: None):
    remaining = iter(devices)
    unresolved = set()

    def publish(address, online, evidence="", mac="", probed=(), verified=()):
        if not cancel.is_set():
            on_result(Availability(address, online, utc_now(), evidence, mac,
                                   tuple(probed), tuple(verified)))

    async def check_port(address, port, is_vnc):
        """Return (reachable, verified); VNC ports also read the RFB greeting."""
        if not is_vnc:
            return await tcp_open(address, port, timeout), False
        service = await probe(address, port, timeout)
        return service is not None, bool(service and service.name == "VNC" and service.verified)

    async def worker():
        for device in remaining:
            if cancel.is_set():
                return
            vnc = sorted(s.port for s in device.services if s.name == "VNC")
            other = sorted(s.port for s in device.services if s.name != "VNC")
            # Try a VNC endpoint and other known services so a stopped VNC server
            # does not mask an otherwise reachable machine.
            ports = (vnc[:1] + other + vnc[1:])[:3]
            vnc_ports = set(vnc)
            checks = await asyncio.gather(*(check_port(device.address, port, port in vnc_ports) for port in ports))
            if any(opened for opened, _ in checks):
                probed = [p for p, (opened, _) in zip(ports, checks) if opened and p in vnc_ports]
                verified = [p for p, (_, ok) in zip(ports, checks) if ok]
                publish(device.address, True, "TCP", probed=probed, verified=verified)
            elif use_ping and await ping_host(device.address, timeout):
                publish(device.address, True, "ping")
            else:
                unresolved.add(device.address)

    async def run():
        await asyncio.gather(*(worker() for _ in range(min(16, len(devices)))))
        if cancel.is_set():
            return

        def arp_found(address, mac):
            if address in unresolved:
                unresolved.remove(address)
                publish(address, True, "ARP", mac)

        targets = {a: source for a, source in (arp_targets or {}).items() if a in unresolved}
        if targets:
            await discover_arp(targets, arp_found, on_warning)
        for address in sorted(unresolved):
            publish(address, False)

    task = asyncio.create_task(run())
    try:
        while not task.done():
            if cancel.is_set():
                task.cancel()
                break
            await asyncio.wait({task}, timeout=0.1)
        if not task.cancelled() and task.done():
            task.result()
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
