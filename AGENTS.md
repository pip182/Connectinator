# Connectinator

PySide6 desktop app for IPv4 device/service discovery and launching installed VNC viewers.

## Commands (PowerShell, project root)
- Python: `.venv\Scripts\python.exe` (Python 3.11+). Use this environment for all tools.
- Install: `.venv\Scripts\python.exe -m pip install -e .`
- Run: `.venv\Scripts\python.exe -m connectinator`
- Test: `.venv\Scripts\python.exe -m unittest discover -s tests -v`

## Map
- `connectinator/app.py`: Qt interface, workers, settings, export.
- `connectinator/scanner.py`: Qt-free async probes, target parsing, scan cancellation.
- `connectinator/discovery.py`: Windows ARP helper; `names.py`: bounded Qt reverse DNS.
- `connectinator/inventory.py`: cached table model and sorting/filtering proxy.
- `connectinator/icons.py`: shared QtAwesome icons; create after QApplication.
- `connectinator/theme.py`: shared control styling and themed dropdowns.
- `connectinator/viewer.py`: viewer discovery and argument-list launch.
- `tests/`: local fake-server and UI tests; no LAN required.

## Working rules
- Read only relevant files; use scoped `rg`. Skip `.venv`, generated files, and broad directory dumps.
- Keep changes focused; prefer stdlib and existing dependencies. Avoid speculative abstractions.
- Keep network/process work off the GUI thread; communicate using Qt signals.
- Emit independent device snapshots; coalesce UI updates and preserve selection by IP.
- Bound concurrency and timeouts; cancellation and window close must clean up workers/sockets/processes.
- Label port-based service guesses separately from protocol-verified results.
- Launch viewers with argument lists, never a shell. Never save VNC credentials.
- Test changed behavior with loopback/mocks; do not scan external networks as a test.
- Run relevant checks once after changes; report outcomes and limitations briefly.
- Keep this file concise; put setup and user instructions in README.md.
