"""Find and launch a VNC viewer without a shell or saved credentials."""

import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys


MAC_APPS = ("TigerVNC Viewer*.app", "VNC Viewer.app", "TightVNC*.app")


def resolve_executable(path: str) -> str:
    """Accept a macOS .app bundle by returning the program inside it."""
    bundle = Path(path)
    if bundle.suffix.lower() != ".app" or not bundle.is_dir():
        return path
    try:
        with (bundle / "Contents" / "Info.plist").open("rb") as stream:
            name = plistlib.load(stream).get("CFBundleExecutable") or bundle.stem
    except (OSError, ValueError, plistlib.InvalidFileException):
        name = bundle.stem
    return str(bundle / "Contents" / "MacOS" / str(name))


def find_viewer() -> str:
    for name in ("vncviewer", "xtigervncviewer", "vncviewer64", "tvnviewer"):
        if executable := shutil.which(name):
            return executable
    if sys.platform == "darwin":
        for root in (Path("/Applications"), Path.home() / "Applications"):
            for pattern in MAC_APPS:
                for bundle in sorted(root.glob(pattern)):
                    if Path(executable := resolve_executable(str(bundle))).is_file():
                        return executable
    for key in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(key)
        if not root:
            continue
        for relative in (
            "TigerVNC/vncviewer.exe", "TightVNC/tvnviewer.exe",
            "uvnc bvba/UltraVNC/vncviewer.exe", "RealVNC/VNC Viewer/vncviewer.exe",
        ):
            path = Path(root) / relative
            if path.is_file():
                return str(path)
    return ""


def viewer_command(executable: str, address: str, port: int, style: str = "Double colon",
                   view_only: bool = False) -> list[str]:
    executable = resolve_executable(executable)
    if not Path(executable).is_file():
        raise ValueError("Choose an installed VNC viewer executable in Viewer settings.")
    separator = ":" if style == "Single colon" else "::"
    target = f"{address}{separator}{port}"
    if not view_only:
        return [executable, target]
    lowered = executable.lower()
    if "tvnviewer" in lowered or "tightvnc" in lowered:
        return [executable, target, "-viewonly=yes"]  # TightVNC options take a value
    if "uvnc" in lowered or "ultravnc" in lowered:
        return [executable, "-viewonly", target]
    return [executable, "-ViewOnly", target]  # TigerVNC / RealVNC


def launch(executable: str, address: str, port: int, style: str, view_only: bool = False) -> None:
    command = viewer_command(executable, address, port, style, view_only)
    if sys.platform == "win32" and getattr(sys, "frozen", False):
        # The bootloader points DLL lookup at its bundled Qt. An external viewer
        # must use its own libraries instead of inheriting that search directory.
        import ctypes
        set_directory = ctypes.WinDLL("kernel32", use_last_error=True).SetDllDirectoryW
        set_directory.argtypes = [ctypes.c_wchar_p]
        set_directory.restype = ctypes.c_int
        if not set_directory(None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            subprocess.Popen(command, shell=False)
        finally:
            set_directory(getattr(sys, "_MEIPASS", None))
    else:
        subprocess.Popen(command, shell=False)
