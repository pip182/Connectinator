"""Find and launch a VNC viewer without a shell or saved credentials."""

import os
from pathlib import Path
import shutil
import subprocess


def find_viewer() -> str:
    for name in ("vncviewer", "vncviewer64", "tvnviewer"):
        if executable := shutil.which(name):
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


def viewer_command(executable: str, address: str, port: int, style: str = "Double colon") -> list[str]:
    if not Path(executable).is_file():
        raise ValueError("Choose an installed VNC viewer executable in Viewer settings.")
    separator = ":" if style == "Single colon" else "::"
    return [executable, f"{address}{separator}{port}"]


def launch(executable: str, address: str, port: int, style: str) -> None:
    subprocess.Popen(viewer_command(executable, address, port, style), shell=False)
