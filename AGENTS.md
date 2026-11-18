# Connectinator

PySide6 desktop app for IPv4 device/service discovery and launching installed remote clients.

## Commands (project root)
- Python 3.11+ in `.venv` (`Scripts\python.exe` on Windows, `bin/python` on Linux/macOS). Use that interpreter for all tools.
- Install: `python -m pip install -e .`
- Run: `run.bat` / `run.sh`, or `python -m connectinator`.
- Test: `python -m unittest discover -s tests -v`
- Linux/macOS compat: `./run.sh compat` or `python scripts/linux_compat_runner.py` (offscreen Qt + loopback self-test).
- EXE: `build.bat` → `dist\Connectinator.exe`; `scripts/build_exe.py` also builds natively on Linux/macOS. Includes a packaged loopback self-test.

## Map
- `connectinator/app.py`: Qt interface, workers, settings, export.
- `connectinator/scanner.py`: Qt-free async probes, target parsing, scan cancellation.
- `connectinator/discovery.py`: Windows ARP helper; `names.py`: bounded Qt reverse DNS.
- `connectinator/inventory.py`: cached table model and sorting/filtering proxy.
- `connectinator/peers.py`: UDP broadcast beacons so running instances list each other (event-driven QUdpSocket).
- `connectinator/storage.py`: SQLite inventory; `monitor.py`: bounded availability checks.
- `connectinator/icons.py`: shared QtAwesome icons; create after QApplication.
- `connectinator/theme.py`: shared control styling, themed dropdowns, and `HelpButton` tooltips.
- `connectinator/remote.py`: cross-platform client discovery and launches (VNC, SSH, RDP, Telnet, HTTP/S, WinRM).
- `connectinator/viewer.py`: VNC viewer discovery and argument-list launch.
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
