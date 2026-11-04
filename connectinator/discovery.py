"""Windows ARP discovery isolated in a killable helper process.

SendARP has no cancellation API. Keeping native calls outside the Qt process lets
Stop/window close terminate them without waiting for the Windows ARP timeout.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
import ipaddress
import json
import socket
import subprocess
import sys
from typing import Callable


def arp_targets_for(addresses: list[str], interfaces: list[tuple[str, int]]) -> dict[str, str]:
    """Map only on-link unicast targets to a source interface (longest prefix wins)."""
    networks = []
    for source, prefix in interfaces:
        ip = ipaddress.IPv4Address(source)
        if prefix < 0 or prefix >= 32 or ip.is_loopback:
            continue
        network = ipaddress.IPv4Network(f"{source}/{prefix}", strict=False)
        networks.append((network, source))
    networks.sort(key=lambda item: item[0].prefixlen, reverse=True)
    own_addresses = {source for source, _ in interfaces}
    result = {}
    for address in addresses:
        ip = ipaddress.IPv4Address(address)
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or address in own_addresses:
            continue
        for network, source in networks:
            if ip in network:
                if network.prefixlen >= 31 or ip not in (network.network_address, network.broadcast_address):
                    result[address] = source
                break
    return result


def _send_arp(address: str, source: str) -> str:
    send = ctypes.WinDLL("iphlpapi.dll").SendARP
    send.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    send.restype = ctypes.c_uint32
    buffer = (ctypes.c_uint32 * 2)()
    length = ctypes.c_uint32(ctypes.sizeof(buffer))
    destination = int.from_bytes(socket.inet_aton(address), byteorder=sys.byteorder)
    origin = int.from_bytes(socket.inet_aton(source), byteorder=sys.byteorder)
    status = send(destination, origin, buffer, ctypes.byref(length))
    if status != 0 or length.value != 6:
        return ""
    mac = bytes(buffer)[:6]
    if mac in (b"\0" * 6, b"\xff" * 6):
        return ""
    return ":".join(f"{byte:02X}" for byte in mac)


def _worker() -> None:
    targets = json.loads(sys.stdin.readline())
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_send_arp, address, source): address for address, source in targets.items()}
        for future in as_completed(futures):
            # Report failed resolutions too, so the parent sees forward progress.
            print(json.dumps({"address": futures[future], "mac": future.result()}), flush=True)


async def discover_arp(targets: dict[str, str], on_device: Callable[[str, str], None],
                       on_warning: Callable[[str], None]) -> None:
    if sys.platform != "win32" or not targets:
        return
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "connectinator.discovery", "--arp-worker",
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        process.stdin.write((json.dumps(targets) + "\n").encode("utf-8"))
        await process.stdin.drain()
        process.stdin.close()
        while line := await asyncio.wait_for(process.stdout.readline(), 15):
            result = json.loads(line)
            address, mac = result["address"], result["mac"]
            if address in targets and mac:
                on_device(address, mac)
        code = await asyncio.wait_for(process.wait(), 1)
        if code:
            on_warning("ARP helper failed; TCP and ping results are still available.")
    except (OSError, TimeoutError, ValueError, KeyError) as exc:
        on_warning(f"ARP discovery unavailable ({type(exc).__name__}); TCP/ping continue.")
    finally:
        if process is not None and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()


if __name__ == "__main__" and sys.argv[1:] == ["--arp-worker"]:
    _worker()
