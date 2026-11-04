"""Bounded, cancellable TCP discovery. No Qt dependency or privileged sockets."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import shutil
import subprocess
import sys
import threading
from dataclasses import asdict, dataclass, field, replace
from typing import Callable

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 515: "LPD", 631: "IPP", 1433: "SQL Server",
    1883: "MQTT", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5901: "VNC", 5902: "VNC", 5903: "VNC",
    5904: "VNC", 5905: "VNC", 5985: "WinRM", 5986: "WinRM TLS",
    8000: "HTTP alternate", 8080: "HTTP alternate", 8443: "HTTPS alternate",
    9100: "Printer",
}
VNC_PORTS = tuple(range(5900, 5910))
COMMON_PORTS = tuple(sorted(set(SERVICES) | set(VNC_PORTS)))
MAX_HOSTS = 4096
MAX_PORTS = 128
# These protocols normally wait for a client request. Keep their passive sniff short
# in the common-services profile; custom scans use the full greeting budget.
CLIENT_FIRST_PORTS = {53, 80, 135, 139, 443, 445, 515, 631, 1433, 1883,
                      3389, 5432, 5985, 5986, 8000, 8080, 8443, 9100}


@dataclass
class Service:
    port: int
    name: str
    verified: bool = False
    banner: str = ""


@dataclass
class Device:
    address: str
    services: list[Service] = field(default_factory=list)
    ping: bool = False
    hostname: str = ""
    label: str = ""
    mac: str = ""
    complete: bool = True

    @property
    def vnc(self) -> list[Service]:
        return [s for s in self.services if s.name == "VNC" and s.verified]

    @property
    def candidates(self) -> list[Service]:
        return [s for s in self.services if s.name == "VNC"]

    def to_dict(self) -> dict:
        return asdict(self)


def parse_targets(text: str) -> list[str]:
    """Accept comma-separated IPv4 addresses, CIDRs, and inclusive IP ranges."""
    addresses: set[ipaddress.IPv4Address] = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            raise ValueError("Enter an IPv4 address, subnet, or IP range.")
        try:
            if "-" in token:
                left, right = token.split("-", 1)
                start, end = ipaddress.IPv4Address(left.strip()), ipaddress.IPv4Address(right.strip())
                count = int(end) - int(start) + 1
                if count < 1 or count > MAX_HOSTS:
                    raise ValueError(f"Ranges must contain 1–{MAX_HOSTS} addresses.")
                values = (ipaddress.IPv4Address(n) for n in range(int(start), int(end) + 1))
            else:
                network = ipaddress.IPv4Network(token, strict=False)
                count = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
                if count > MAX_HOSTS:
                    raise ValueError(f"Choose a smaller subnet (maximum {MAX_HOSTS} hosts).")
                values = network.hosts()
            for address in values:
                if address.is_multicast or address.is_unspecified or int(address) == 0xFFFFFFFF:
                    raise ValueError("Use unicast IPv4 addresses.")
                addresses.add(address)
                if len(addresses) > MAX_HOSTS:
                    raise ValueError(f"Maximum {MAX_HOSTS} hosts per scan.")
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"Invalid IPv4 target: {token}") from exc
    return [str(a) for a in sorted(addresses)]


def parse_ports(text: str) -> tuple[int, ...]:
    ports: set[int] = set()
    try:
        for token in text.split(","):
            if "-" in token:
                first, last = (int(v.strip()) for v in token.split("-", 1))
            else:
                first = last = int(token.strip())
            if not 1 <= first <= last <= 65535 or last - first + 1 > MAX_PORTS:
                raise ValueError
            ports.update(range(first, last + 1))
            if len(ports) > MAX_PORTS:
                raise ValueError
    except ValueError as exc:
        raise ValueError(f"Enter ports 1–65535, at most {MAX_PORTS} (e.g. 22,80,5900-5909).") from exc
    return tuple(sorted(ports))


async def probe(address: str, port: int, timeout: float, greeting_timeout: float | None = None,
                *, quick_greetings: bool = False) -> Service | None:
    greeting_timeout = timeout if greeting_timeout is None else greeting_timeout
    if quick_greetings and port in CLIENT_FIRST_PORTS:
        greeting_timeout = min(greeting_timeout, 0.1)
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
        banner = b""
        try:
            # RFB's server greeting is exactly 12 bytes; tolerate fragmented delivery.
            banner = await asyncio.wait_for(reader.readexactly(12), greeting_timeout)
        except asyncio.IncompleteReadError as exc:
            banner = exc.partial
        except (TimeoutError, OSError):
            pass
        decoded = banner.decode("ascii", errors="replace").strip()
        if re.fullmatch(rb"RFB \d{3}\.\d{3}\n", banner):
            return Service(port, "VNC", True, decoded)
        if banner.startswith(b"SSH-"):
            return Service(port, "SSH", True, decoded)
        name = SERVICES.get(port, "VNC" if 5900 <= port <= 5999 else "Unknown TCP")
        return Service(port, name, False, decoded)
    except (TimeoutError, OSError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 0.2)
            except (TimeoutError, OSError):
                pass


async def ping_host(address: str, timeout: float) -> bool:
    executable = shutil.which("ping")
    if not executable:
        return False
    if sys.platform == "win32":
        args = ["-n", "1", "-w", str(math.ceil(timeout * 1000)), address]
    elif sys.platform == "darwin":
        args = ["-n", "-c", "1", "-W", str(math.ceil(timeout * 1000)), address]
    else:
        args = ["-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), address]
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            executable, *args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            **({"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}),
        )
        output, _ = await asyncio.wait_for(process.communicate(), timeout + 0.5)
        # Windows can return zero for an ICMP "destination unreachable" response.
        return process.returncode == 0 and (sys.platform != "win32" or b"ttl=" in output.lower())
    except (TimeoutError, OSError):
        return False
    finally:
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()


async def scan(
    addresses: list[str], ports: tuple[int, ...], timeout: float,
    cancel: threading.Event, on_device: Callable[[Device], None],
    on_progress: Callable[[int, int], None], *, use_ping: bool = True,
    greeting_timeout: float = 0.5, quick_greetings: bool = True,
    arp_targets: dict[str, str] | None = None,
    on_warning: Callable[[str], None] = lambda _: None,
) -> None:
    """Publish immutable snapshots as services arrive; never gate TCP on ping/ARP."""
    from .discovery import discover_arp

    pending = iter(addresses)
    sockets = asyncio.Semaphore(128)
    completed = 0
    records: dict[str, Device] = {}
    priority = tuple(p for p in ports if 5900 <= p <= 5999 and p not in (5985, 5986))
    remaining = tuple(p for p in ports if p not in priority)

    def record(address: str) -> Device:
        if address not in records:
            records[address] = Device(address, complete=False)
        return records[address]

    def publish(device: Device) -> None:
        if not cancel.is_set() and (device.services or device.ping or device.mac):
            # Qt's object signals carry references: never send the mutable accumulator.
            on_device(replace(device, services=list(device.services)))

    def arp_found(address: str, mac: str) -> None:
        device = record(address)
        device.mac = mac
        publish(device)

    async def limited_probe(address: str, port: int) -> Service | None:
        async with sockets:
            service = await probe(address, port, timeout, greeting_timeout,
                                  quick_greetings=quick_greetings)
        if service is not None:
            device = record(address)
            device.services.append(service)
            device.services.sort(key=lambda s: s.port)
            publish(device)
        return service

    async def check_ping(address: str) -> None:
        if use_ping and await ping_host(address, timeout):
            device = record(address)
            device.ping = True
            publish(device)

    async def check_ports(address: str) -> None:
        # Finish the VNC phase before letting slower general-service probes queue.
        for group in (priority, remaining):
            await asyncio.gather(*(limited_probe(address, port) for port in group))

    async def worker() -> None:
        nonlocal completed
        for address in pending:
            if cancel.is_set():
                return
            await asyncio.gather(check_ports(address), check_ping(address))
            device = record(address)
            device.complete = True
            publish(device)
            completed += 1
            on_progress(completed, len(addresses))

    tasks = [asyncio.create_task(worker()) for _ in range(min(16, len(addresses)))]
    if arp_targets and not cancel.is_set():
        tasks.append(asyncio.create_task(discover_arp(arp_targets, arp_found, on_warning)))
    try:
        while tasks:
            if cancel.is_set():
                break
            done, _ = await asyncio.wait(tasks, timeout=0.1, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            tasks = [task for task in tasks if not task.done()]
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
