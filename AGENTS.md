# Connectinator

PySide6 desktop app for IPv4 device/service discovery and launching installed VNC viewers.

## Commands (PowerShell, project root)
- Python: `.venv\Scripts\python.exe` (Python 3.11+); `.venv/bin/python` on Linux/macOS. Use this environment for all tools.
- Install: `.venv\Scripts\python.exe -m pip install -e .`
- Run: `.venv\Scripts\python.exe -m connectinator`
- Test: `.venv\Scripts\python.exe -m unittest discover -s tests -v`
- EXE: `build.bat` → `dist\Connectinator.exe`; `scripts/build_exe.py` also builds natively on Linux/macOS. Includes a packaged loopback self-test.

## Map
- `connectinator/app.py`: Qt interface, workers, settings, export.
- `connectinator/scanner.py`: Qt-free async probes, target parsing, scan cancellation.
- `connectinator/discovery.py`: Windows ARP helper; `names.py`: bounded Qt reverse DNS.
- `connectinator/inventory.py`: cached table model and sorting/filtering proxy.
- `connectinator/peers.py`: UDP broadcast beacons so running instances list each other (event-driven QUdpSocket).
- `connectinator/storage.py`: SQLite inventory; `monitor.py`: bounded availability checks.
- `connectinator/icons.py`: shared QtAwesome icons; create after QApplication.
- `connectinator/theme.py`: shared control styling and themed dropdowns.
- `connectinator/viewer.py`: viewer discovery and argument-list launch.
- `connectinator/launcher.py`: GUI/worker dispatch; `scripts/build_exe.py`: PyInstaller build.
- `tests/`: local fake-server and UI tests; no LAN required.

## Working rules
- Read only relevant files; use scoped `rg`. Skip `.venv`, generated files, and broad directory dumps.
- Keep changes focused; prefer stdlib and existing dependencies. Avoid speculative abstractions.
- Keep network/process work off the GUI thread; communicate using Qt signals.
- Emit independent device snapshots; coalesce UI updates and preserve selection by IP.
- Reload reachability as unchecked; preserve offline metadata. Never overlap scans and monitoring.
- Bound concurrency and timeouts; cancellation and window close must clean up workers/sockets/processes.
- Label port-based service guesses separately from protocol-verified results.
- Launch viewers with argument lists, never a shell. Never save VNC credentials.
- Test changed behavior with loopback/mocks; do not scan external networks as a test. Tests disable peer broadcasts.
- Keep Windows-only APIs guarded (`sys.platform`, `NO_WINDOW`); the app must run on Windows, macOS, and Linux.
- Run relevant checks once after changes; report outcomes and limitations briefly.
- Keep this file concise; put setup and user instructions in README.md.
