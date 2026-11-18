"""Run unit tests and the loopback self-test on Linux/macOS (offscreen Qt)."""

from pathlib import Path
import json
import os
import subprocess
import sys


def main():
    if sys.platform == "win32":
        raise SystemExit("On Windows, use: python -m unittest discover -s tests -v and scripts/build_exe.py")
    root = Path(__file__).resolve().parents[1]
    venv_python = root / ".venv" / "bin" / "python"
    python = venv_python if venv_python.is_file() else Path(sys.executable)
    if not venv_python.is_file():
        print("Warning: .venv/bin/python not found; using current interpreter.", file=sys.stderr)
    env = os.environ.copy()
    env.setdefault("QT_QPA_PLATFORM", "offscreen")

    print("Running unit tests …")
    tests = subprocess.run(
        [str(python), "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=root,
        env=env,
    )
    if tests.returncode:
        raise SystemExit(tests.returncode)

    build = root / "build"
    build.mkdir(exist_ok=True)
    report_path = build / "linux-compat-self-test.json"
    print(f"Running loopback self-test → {report_path}")
    smoke = subprocess.run(
        [str(python), "-m", "connectinator", "--self-test", str(report_path)],
        cwd=root,
        env=env,
    )
    if smoke.returncode:
        raise SystemExit(smoke.returncode)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not report.get("passed"):
        raise SystemExit(f"Self-test reported failure: {report}")
    print("Linux compatibility checks passed.")


if __name__ == "__main__":
    main()