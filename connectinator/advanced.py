"""Bounded, read-only advanced checks for one device.

No Qt dependency, no credentials, no shell, and no exploitation: this module only
connects to TCP ports, reads short banners, and makes one harmless HTTP GET to `/`.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field, replace
import math
import re
import shutil
import ssl
import subprocess
import sys
from typing import Callable

from .scanner import NO_WINDOW, Service, probe


def _port_set() -> tuple[int, ...]:
    ports = {
        21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 113, 119, 123,
        135, 137, 139, 143, 161, 162, 179, 389, 427, 443, 445, 465, 500,
        512, 513, 514, 515, 520, 548, 554, 587, 593, 623, 631, 636, 873,
        902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080,
        1099, 1194, 1433, 1434, 1521, 1720, 1723, 1883, 1900, 2049,
        2082, 2083, 2086, 2087, 2121, 2181, 2375, 2376, 2483, 2484,
        3128, 3268, 3269, 3306, 3389, 3690, 4369, 4443, 4444, 4500,
        5000, 5060, 5061, 5432, 5601, 5631, 5632, 5672, 5984, 5985,
        5986, 6000, 6001, 6379, 6443, 6666, 6667, 7001, 7002, 7070,
        8000, 8008, 8022, 8080, 8081, 8082, 8088, 8090, 8161, 8181,
        8222, 8443, 8500, 8530, 8531, 8554, 8649, 8880, 8888, 9000,
        9001, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 10000,
        11211, 15672, 16384, 27017, 32400,
    }
    ports.update(range(5900, 5911))
    return tuple(sorted(ports))


ADVANCED_PORTS = _port_set()
ADVANCED_CONCURRENCY = 32
SEVERITY_ORDER = {"warning": 0, "note": 1, "info": 2}
HTTP_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8081, 8082, 8088, 8090,
                        8443, 8880, 8888, 9000, 9443, 10000})
VNC_PORTS = frozenset(range(5900, 5911))
TLS_PORTS = frozenset({443, 8443, 9443})
GREETING_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                  110: "POP3", 143: "IMAP"}
RFB_RE = re.compile(rb"RFB (\d{3})\.(\d{3})\n")
SECURITY_NAMES = {1: "None", 2: "VNC Authentication", 18: "TLS",
                  19: "VeNCrypt", 30: "Diffie-Hellman",
                  32: "UltraVNC MSLOGON"}
COMMON_OUIS = {
    "00:0C:29": "VMware", "00:15:6D": "HP", "00:1A:4B": "Cisco",
    "00:1B:21": "Intel", "00:25:90": "Supermicro", "00:1D:7D": "Apple",
    "18:B4:30": "Nest", "3C:52:82": "Raspberry Pi", "A4:83:E7": "Apple",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "F0:9F:C2": "Ubiquiti",
}


@dataclass(frozen=True)
class Finding:
    category: str
    title: str
    detail: str
    port: int = 0
    severity: str = "info"  # info, note, or warning


@dataclass
class AdvancedReport:
    address: str
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    fingerprint: str = ""
    ports_scanned: int = 0
    reachable: bool = False
    partial: bool = False
    checked_ports: tuple[int, ...] = field(default_factory=tuple)
    completed_ports: int = 0

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "services": [asdict(service) for service in self.services],
            "findings": [asdict(finding) for finding in self.findings],
            "fingerprint": self.fingerprint,
            "ports_scanned": self.ports_scanned,
            "reachable": self.reachable,
            "partial": self.partial,
            "checked_ports": list(self.checked_ports),
            "completed_ports": self.completed_ports,
        }


def _printable(data: bytes, limit: int = 4096) -> str:
    text = data[:limit].decode("utf-8", "replace")
    return "".join(ch if ch in "\n\r\t" or 32 <= ord(ch) < 127 else " "
                   for ch in text).strip()


async def _connect(address: str, port: int, timeout: float, context=None):
    return await asyncio.wait_for(asyncio.open_connection(address, port, ssl=context), timeout)


async def _close(writer) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 0.2)
    except (TimeoutError, OSError):
        pass


async def _read(reader, limit: int, timeout: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(limit), timeout)
    except (TimeoutError, OSError):
        return b""


async def _readline(reader, timeout: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.readline(), timeout)
    except (TimeoutError, OSError, ValueError):
        return b""


async def _read_exactly(reader, count: int, timeout: float) -> bytes:
    """Collect `count` bytes without assuming they arrive in one packet."""
    if count <= 0:
        return b""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        left = deadline - loop.time()
        if left <= 0:
            break
        chunk = await _read(reader, remaining, left)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


async def _read_until(reader, delimiters: tuple[bytes, ...], limit: int, timeout: float) -> bytes:
    """Read until a delimiter appears, the cap is hit, or the total timeout expires."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    data = bytearray()
    while len(data) < limit and not any(delimiter in data for delimiter in delimiters):
        left = deadline - loop.time()
        if left <= 0:
            break
        chunk = await _read(reader, min(4096, limit - len(data)), left)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Banner reading only; never trust this for a connection.
    return context


def ping_ttl(address: str, timeout: float) -> int | None:
    """Best-effort TTL from the system ping utility; None when unavailable."""
    executable = shutil.which("ping")
    if not executable:
        return None
    if sys.platform == "win32":
        args = ["-n", "1", "-w", str(math.ceil(timeout * 1000)), address]
    elif sys.platform == "darwin":
        args = ["-n", "-c", "1", "-W", str(math.ceil(timeout * 1000)), address]
    else:
        args = ["-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), address]
    try:
        result = subprocess.run([executable, *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=timeout + 0.5, check=False,
                                creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(rb"ttl[=:]\s*(\d+)", result.stdout, re.IGNORECASE)
    return int(match.group(1)) if match else None


async def _vnc_probe(address: str, port: int, timeout: float):
    findings = []
    reader, writer = await _connect(address, port, timeout)
    try:
        banner = await _read_exactly(reader, 12, timeout)
        if len(banner) < 12:
            return Service(port, "VNC", False, source="advanced"), findings
        match = RFB_RE.fullmatch(banner)
        if not match:
            return Service(port, "VNC", False, _printable(banner), source="advanced"), findings
        major, minor = int(match.group(1)), int(match.group(2))
        types: list[int] = []
        if major >= 3 and minor >= 7:
            count = await _read_exactly(reader, 1, min(timeout, 0.5))
            if count:
                types = list(await _read_exactly(reader, count[0], min(timeout, 0.5)))
        else:
            raw = await _read_exactly(reader, 4, min(timeout, 0.5))
            if len(raw) >= 4:
                types = [int.from_bytes(raw[:4], "big")]
        names = [SECURITY_NAMES.get(value, f"type {value}") for value in types]
        banner_text = f"RFB {major}.{minor:03d}" + (f" · {', '.join(names)}" if names else "")
        if 1 in types:
            findings.append(Finding("Access", "VNC advertises unauthenticated access",
                                    "The RFB security types include None. No session was opened; "
                                    "confirm ownership and restrict viewer access.", port, "warning"))
        if (major, minor) < (3, 8):
            findings.append(Finding("Version", "Old RFB version in banner",
                                    f"The server announced RFB {major}.{minor}; upgrade it if supported.",
                                    port, "note"))
        return Service(port, "VNC", True, banner_text, source="advanced"), findings
    finally:
        await _close(writer)


def _parse_http(data: bytes) -> tuple[str, dict[str, str]]:
    lines = _printable(data).splitlines()
    status = lines[0].strip() if lines and lines[0].lower().startswith("http/") else ""
    headers = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return status, headers


async def _http_probe(address: str, port: int, timeout: float, context=None):
    findings = []
    reader, writer = await _connect(address, port, timeout, context)
    try:
        request = (f"GET / HTTP/1.0\r\nHost: {address}\r\n"
                   "User-Agent: Connectinator/1.0\r\nConnection: close\r\n\r\n").encode("ascii")
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout)
        name = "HTTPS" if context else "HTTP"
        response = await _read_until(reader, (b"\r\n\r\n", b"\n\n"), 8192, min(timeout, 1.0))
        head, separator, body = response.partition(b"\r\n\r\n")
        if not separator:
            head, separator, body = response.partition(b"\n\n")
        if not separator:
            head, body = response, b""
        if len(body) < 4096:
            body += await _read(reader, 4096 - len(body), min(timeout, 0.4))
        status, headers = _parse_http(head + separator)
        if not status:
            return Service(port, name, False, source="advanced"), findings
        server = headers.get("server", "")
        banner = status + (f" · {server}" if server else "")
        match = re.search(r"\b(\d{3})\b", status.split(" ", 1)[-1])
        code = int(match.group(1)) if match else 0
        body_text = _printable(body).casefold()
        if code == 200 and ("index of" in body_text or "directory listing" in body_text):
            findings.append(Finding("Access", "HTTP directory listing at /",
                                    "The root page appears to list directory contents. Restrict exposure "
                                    "if this was not intended.", port, "warning"))
        if "www-authenticate" in headers:
            findings.append(Finding("Access", "HTTP root requires authentication",
                                    "The server sent a WWW-Authenticate challenge for /.", port, "info"))
        if re.search(r"apache/1\.|apache/2\.2|nginx/0\.|nginx/1\.[0-9]\b|iis/6\.0", server, re.I):
            findings.append(Finding("Version", "Old web server version in banner",
                                    f"Server header: {server}. Treat as a potential risk, not a confirmed issue.",
                                    port, "note"))
        redirect = headers.get("location", "")
        if not context and redirect.startswith("https://"):
            findings.append(Finding("Access", "HTTP redirects to HTTPS",
                                    f"Root redirect: {redirect[:160]}", port, "info"))
        return Service(port, name, True, banner, source="advanced"), findings
    finally:
        await _close(writer)


async def _greeting_probe(address: str, port: int, timeout: float):
    expected = GREETING_PORTS[port]
    findings = []
    reader, writer = await _connect(address, port, timeout)
    try:
        data = await _readline(reader, min(timeout, 1.0)) or await _read(reader, 512, min(timeout, 0.5))
        text = _printable(data, 512)
        verified = False
        if expected == "SSH" and text.startswith("SSH-"):
            verified = True
            parts = text.split("-", 2)
            software = parts[2] if len(parts) > 2 else ""
            if parts[1].startswith("1") or re.search(r"OpenSSH_[0-6]\.", software, re.I):
                findings.append(Finding("Version", "Old SSH version in banner",
                                        f"Banner: {text[:160]}. Verify with the device owner.",
                                        port, "note"))
        elif expected == "Telnet":
            verified = b"\xff" in data or "login" in text.casefold() or "user" in text.casefold()
            if verified:
                findings.append(Finding("Access", "Plaintext Telnet service reachable",
                                        "Telnet sends credentials and sessions without encryption. "
                                        "Prefer SSH where possible.", port, "warning"))
        elif expected == "FTP" and text.startswith("220"):
            verified = True
            findings.append(Finding("Access", "Plaintext FTP service reachable",
                                    "FTP credentials and data are unencrypted unless TLS is enforced.",
                                    port, "note"))
        elif expected == "SMTP" and text.startswith("220"):
            verified = True
        elif expected == "POP3" and text.startswith("+OK"):
            verified = True
        elif expected == "IMAP" and text.startswith("* OK"):
            verified = True
        if expected in ("SMTP", "POP3", "IMAP") and verified:
            findings.append(Finding("Access", "Unencrypted mail service reachable",
                                    f"{expected} answered without TLS on this port.", port, "note"))
        return Service(port, expected, verified, text[:240], source="advanced"), findings
    finally:
        await _close(writer)


async def _generic_probe(address: str, port: int, timeout: float):
    service = await probe(address, port, timeout, min(timeout, 0.3))
    if service is not None:
        service = replace(service, source="advanced")
    return service, []


async def _inspect_port(address: str, port: int, timeout: float, context):
    if port in HTTP_PORTS:
        return await _http_probe(address, port, timeout, context if port in TLS_PORTS else None)
    if port in GREETING_PORTS:
        return await _greeting_probe(address, port, timeout)
    if port in VNC_PORTS:
        return await _vnc_probe(address, port, timeout)
    return await _generic_probe(address, port, timeout)


def _fingerprint(hostname: str, mac: str, ttl: int | None, services: list[Service]) -> str:
    hints = []
    if ttl is not None:
        if ttl <= 64:
            hints.append("TTL suggests a Linux/macOS/Unix-like host")
        elif ttl <= 128:
            hints.append("TTL suggests a Windows host")
        else:
            hints.append("TTL suggests a network appliance")
    if mac:
        normalized = mac.upper().replace("-", ":")
        vendor = COMMON_OUIS.get(normalized[:8])
        hints.append(f"MAC {mac}" + (f" ({vendor})" if vendor else ""))
    ports = {service.port for service in services}
    if ports & {515, 631, 9100}:
        hints.append("printer-like services")
    if 3389 in ports:
        hints.append("RDP/Windows-like service")
    if 22 in ports:
        hints.append("SSH host")
    if hostname:
        hints.append(f"hostname {hostname}")
    return "; ".join(dict.fromkeys(hints)) or "No strong fingerprint hints"


async def advanced_scan(
    address: str,
    timeout: float,
    cancel: Callable[[], bool],
    on_progress: Callable[[int, int], None] = lambda _completed, _total: None,
    *,
    ports: tuple[int, ...] | None = None,
    mac: str = "",
    hostname: str = "",
    on_update: Callable[[AdvancedReport], None] = lambda _report: None,
) -> AdvancedReport:
    """Scan one address with short, read-only probes; return partial results on cancel."""
    selected = ports if ports is not None else ADVANCED_PORTS
    report = AdvancedReport(address=address, ports_scanned=len(selected))
    semaphore = asyncio.Semaphore(ADVANCED_CONCURRENCY)
    context = _tls_context()
    checked_ports: list[int] = []
    completed = 0
    loop = asyncio.get_running_loop()
    last_update = 0.0

    def sorted_services() -> list[Service]:
        return sorted(report.services, key=lambda service: service.port)

    def sorted_findings() -> list[Finding]:
        return sorted(report.findings, key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, 99), finding.port, finding.title,
        ))

    def finalize():
        report.checked_ports = tuple(sorted(checked_ports))
        report.completed_ports = completed
        report.services[:] = sorted_services()
        report.findings[:] = sorted_findings()
        if not report.reachable:
            report.reachable = bool(report.services)
        if not report.fingerprint:
            report.fingerprint = _fingerprint(hostname, mac, None, report.services)

    def emit_update():
        nonlocal last_update
        now = loop.time()
        if now - last_update < 0.2:
            return
        last_update = now
        snapshot = AdvancedReport(
            address=address,
            services=list(sorted_services()),
            findings=list(sorted_findings()),
            ports_scanned=len(selected),
            reachable=bool(report.services),
            partial=True,
            checked_ports=tuple(sorted(checked_ports)),
            completed_ports=completed,
        )
        try:
            on_update(snapshot)
        except Exception:
            pass  # A UI callback must never abort the scan.

    async def inspect(port: int):
        nonlocal completed
        service, findings = None, []
        attempted = False
        try:
            async with semaphore:
                if cancel():
                    on_progress(completed, len(selected))
                    return
                attempted = True
                service, findings = await _inspect_port(address, port, timeout, context)
        except Exception:
            pass
        if service is not None:
            report.services.append(service)
        report.findings.extend(findings)
        if attempted:
            checked_ports.append(port)
            completed += 1
            emit_update()
        on_progress(completed, len(selected))

    async def run():
        ttl_task = asyncio.create_task(asyncio.to_thread(ping_ttl, address, min(timeout, 1.0)))
        try:
            await asyncio.gather(*(inspect(port) for port in selected))
            try:
                ttl = await asyncio.wait_for(ttl_task, 0.2)
            except (TimeoutError, asyncio.CancelledError):
                ttl = None
        finally:
            if not ttl_task.done():
                ttl_task.cancel()
                await asyncio.gather(ttl_task, return_exceptions=True)
        report.reachable = bool(report.services) or ttl is not None
        report.fingerprint = _fingerprint(hostname, mac, ttl, report.services)
        if ttl is not None:
            report.findings.append(Finding("Fingerprint", "TTL-based host hint",
                                           f"ping returned TTL {ttl}; NAT or firewalls can change it.",
                                           0, "info"))
        finalize()
        return report

    task = asyncio.create_task(run())
    try:
        while not task.done():
            if cancel():
                task.cancel()
                break
            await asyncio.wait({task}, timeout=0.1)
        if task.done() and not task.cancelled():
            return task.result()
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    report.partial = True
    finalize()
    return report
