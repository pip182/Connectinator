"""Discover and launch installed remote clients without a shell or saved passwords."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import shutil
import subprocess
import sys

import webbrowser

from .scanner import Service
from .viewer import find_viewer, launch as launch_vnc, viewer_command

CONNECTABLE = frozenset({"VNC", "SSH", "RDP", "Telnet", "HTTP", "HTTPS", "WinRM"})
CLIENT_KINDS = frozenset({"VNC", "SSH", "RDP", "Telnet", "WinRM"})
BROWSER_KINDS = frozenset({"HTTP", "HTTPS"})


def service_kind(service: Service) -> str | None:
    if service.name in {"WinRM", "WinRM TLS"}:
        return "WinRM" if sys.platform == "win32" else None
    if service.name in CONNECTABLE:
        return service.name
    if service.name in ("HTTP alternate",):
        return "HTTP"
    if service.name in ("HTTPS alternate",):
        return "HTTPS"
    if 5900 <= service.port <= 5999 and service.name in {"VNC", "Unknown TCP"}:
        return "VNC"
    return None


def favorite_ref(kind: str, port: int) -> str:
    return f"{kind}:{port}"


def parse_favorite_ref(value) -> tuple[str, int] | None:
    if isinstance(value, str) and ":" in value:
        kind, port_text = value.split(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            return None
        if kind and 1 <= port <= 65535:
            return kind, port
    if isinstance(value, int) and 1 <= value <= 65535:
        return "VNC", value
    return None


def favorite_service(kind: str, port: int) -> Service:
    name = {"HTTP": "HTTP", "HTTPS": "HTTPS", "WinRM": "WinRM"}.get(kind, kind)
    return Service(port, name)


def find_ssh() -> str:
    if executable := shutil.which("ssh"):
        return executable
    for root in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if not root:
            continue
        candidate = Path(root) / "PuTTY" / "putty.exe"
        if candidate.is_file():
            return str(candidate)
    return ""


def find_rdp() -> str:
    if sys.platform == "win32":
        candidate = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "mstsc.exe"
        if candidate.is_file():
            return str(candidate)
    for name in ("xfreerdp", "xfreerdp3", "rdesktop", "remmina"):
        if executable := shutil.which(name):
            return executable
    if sys.platform == "darwin":
        app = Path("/Applications/Microsoft Remote Desktop.app/Contents/MacOS/Microsoft Remote Desktop")
        if app.is_file():
            return str(app)
    return ""


def find_telnet() -> str:
    return shutil.which("telnet") or ""


def find_winrm() -> str:
    if sys.platform != "win32":
        return ""
    for name in ("pwsh", "powershell"):
        if executable := shutil.which(name):
            return executable
    return ""


def find_client(kind: str) -> str:
    if kind == "VNC":
        return find_viewer()
    if kind == "SSH":
        return find_ssh()
    if kind == "RDP":
        return find_rdp()
    if kind == "Telnet":
        return find_telnet()
    if kind == "WinRM":
        return find_winrm()
    if kind in BROWSER_KINDS:
        return ""
    raise ValueError(f"Unsupported remote service: {kind}")


def browser_url(kind: str, address: str, port: int) -> str:
    scheme = "https" if kind == "HTTPS" else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{address}"
    return f"{scheme}://{address}:{port}"


def _require_executable(kind: str, executable: str) -> str:
    if not executable or not Path(executable).is_file():
        raise ValueError(f"Choose an installed {kind} client in Remote client settings.")
    return executable


def client_command(
    kind: str,
    executable: str,
    address: str,
    port: int,
    *,
    vnc_style: str = "Double colon",
    view_only: bool = False,
    ssh_user: str = "",
) -> list[str]:
    executable = _require_executable(kind, executable)
    if kind == "VNC":
        return viewer_command(executable, address, port, vnc_style, view_only)
    if kind == "SSH":
        user = (ssh_user or getpass.getuser()).strip() or getpass.getuser()
        if executable.lower().endswith("putty.exe"):
            return [executable, "-ssh", f"{user}@{address}", "-P", str(port)]
        return [executable, "-p", str(port), f"{user}@{address}"]
    if kind == "RDP":
        target = f"{address}:{port}" if port != 3389 else address
        name = Path(executable).name.lower()
        if name == "mstsc.exe":
            return [executable, f"/v:{target}"]
        if "xfreerdp" in name:
            return [executable, f"/v:{address}", f"/port:{port}"]
        if name == "rdesktop":
            return [executable, "-p", str(port), address]
        if name == "remmina":
            return [executable, "-c", f"rdp://{address}:{port}"]
        return [executable, target]
    if kind == "Telnet":
        return [executable, address, str(port)]
    if kind == "WinRM":
        use_ssl = port == 5986
        session = f"Enter-PSSession -ComputerName {address} -Port {port}"
        if use_ssl:
            session += " -UseSSL"
        return [executable, "-NoExit", "-Command", session]
    raise ValueError(f"Unsupported remote service: {kind}")


def launch_client(
    kind: str,
    executable: str,
    address: str,
    port: int,
    *,
    vnc_style: str = "Double colon",
    view_only: bool = False,
    ssh_user: str = "",
    browser_executable: str = "",
) -> None:
    if kind in BROWSER_KINDS:
        url = browser_url(kind, address, port)
        if browser_executable and Path(browser_executable).is_file():
            subprocess.Popen([browser_executable, url], shell=False)
            return
        if not webbrowser.open(url):
            raise ValueError("Could not open the system default browser.")
        return
    if kind == "VNC":
        launch_vnc(executable, address, port, vnc_style, view_only)
        return
    command = client_command(kind, executable, address, port, vnc_style=vnc_style,
                             view_only=view_only, ssh_user=ssh_user)
    subprocess.Popen(command, shell=False)