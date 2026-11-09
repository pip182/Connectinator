"""Build the single-file Windows app using the project's active environment."""

from pathlib import Path
import argparse
import json
import subprocess
import sys


def main():
    if sys.platform != "win32":
        raise SystemExit("Build the Windows executable on Windows.")
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", default="dist", help="Output directory, relative to the project root")
    args = parser.parse_args()
    output = (root / args.dist_dir).resolve()
    sys.path.insert(0, str(root))
    from PySide6.QtWidgets import QApplication
    from connectinator.icons import icon

    app = QApplication.instance() or QApplication([])
    build = root / "build"
    build.mkdir(exist_ok=True)
    app_icon = build / "connectinator.ico"
    if not icon("network-wired", "#58dfb3").pixmap(256, 256).save(str(app_icon), "ICO"):
        raise SystemExit("Could not generate the application icon.")
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm",
               "--onefile", "--windowed", "--name", "Connectinator",
               "--paths", str(root), "--specpath", str(build),
               "--workpath", str(build / "pyinstaller"), "--distpath", str(output),
               "--icon", str(app_icon), "--collect-data", "qtawesome",
               "--hidden-import", "PySide6.QtSvg", "--add-data", f"{root / 'LICENSE.md'};."]
    for module in ("tkinter", "unittest", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
                   "PySide6.QtWebEngineQuick", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
                   "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets",
                   "PySide6.QtDataVisualization"):
        command.extend(["--exclude-module", module])
    command.append(str(root / "packaging" / "windows_entry.py"))
    subprocess.run(command, cwd=root, check=True)
    executable = output / "Connectinator.exe"
    report_path = build / "exe-self-test.json"
    completed = subprocess.run([str(executable), "--self-test", str(report_path)], cwd=build,
                               timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if completed.returncode or not report.get("passed") or not report.get("frozen"):
        raise SystemExit(f"Packaged application self-test failed: {report}")
    print(f"Built and verified {executable}")


if __name__ == "__main__":
    main()
