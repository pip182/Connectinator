"""Build a standalone app for the current OS using the project's active environment.

Windows: dist/Connectinator.exe. Linux: dist/Connectinator. macOS: dist/Connectinator.app.
PyInstaller cannot cross-compile, so build on each target operating system.
"""

from pathlib import Path
import argparse
import json
import os
import subprocess
import sys


def main():
    windows, mac = sys.platform == "win32", sys.platform == "darwin"
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", default="dist", help="Output directory, relative to the project root")
    args = parser.parse_args()
    output = (root / args.dist_dir).resolve()
    if not windows and not mac and not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # Headless Linux build hosts; inherited by the self-test.
    sys.path.insert(0, str(root))
    from PySide6.QtWidgets import QApplication
    from connectinator.icons import icon

    app = QApplication.instance() or QApplication([])
    build = root / "build"
    build.mkdir(exist_ok=True)
    # PyInstaller reads .ico directly; macOS needs Pillow to convert a PNG to .icns.
    app_icon = build / ("connectinator.ico" if windows else "connectinator.png")
    if not icon("network-wired", "#58dfb3").pixmap(256, 256).save(str(app_icon), "ICO" if windows else "PNG"):
        raise SystemExit("Could not generate the application icon.")
    # A macOS GUI app must be an .app bundle (one-folder); elsewhere use one file.
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm",
               "--onedir" if mac else "--onefile", "--windowed", "--name", "Connectinator",
               "--paths", str(root), "--specpath", str(build),
               "--workpath", str(build / "pyinstaller"), "--distpath", str(output),
               "--collect-data", "qtawesome", "--hidden-import", "PySide6.QtSvg",
               "--add-data", f"{root / 'LICENSE.md'}{os.pathsep}."]
    if windows or mac:
        command.extend(["--icon", str(app_icon)])
    for module in ("tkinter", "unittest", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
                   "PySide6.QtWebEngineQuick", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
                   "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets",
                   "PySide6.QtDataVisualization"):
        command.extend(["--exclude-module", module])
    command.append(str(root / "packaging" / "windows_entry.py"))
    subprocess.run(command, cwd=root, check=True)
    if windows:
        product = executable = output / "Connectinator.exe"
    elif mac:
        product = output / "Connectinator.app"
        executable = product / "Contents" / "MacOS" / "Connectinator"
    else:
        product = executable = output / "Connectinator"
    report_path = build / "exe-self-test.json"
    completed = subprocess.run([str(executable), "--self-test", str(report_path)], cwd=build,
                               timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if completed.returncode or not report.get("passed") or not report.get("frozen"):
        raise SystemExit(f"Packaged application self-test failed: {report}")
    print(f"Built and verified {product}")


if __name__ == "__main__":
    main()
