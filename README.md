# Connectinator

A PySide6 desktop app for discovering IPv4 devices, inspecting common TCP services,
and quickly connecting to VNC servers with an installed viewer. Icons use QtAwesome.
It runs on Windows, macOS, and Linux, and copies running on the same network find
each other automatically (see **Other computers running Connectinator**).

## Setup and launch

Python 3.11 or newer is required. A project-local `.venv` keeps dependencies isolated.

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\python.exe -m connectinator
```

On Windows, double-click **run.bat** in the project root to launch with this environment.
It works from another current directory and leaves startup errors visible.
All dependencies are defined in `pyproject.toml`; install them with the editable
install command above.

The environment has already been created for this checkout. To activate it optionally:

```powershell
.\.venv\Scripts\Activate.ps1
```

Activation is unnecessary when using the full interpreter path above.

On Linux or macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
./run.sh
```

`run.sh` launches with the project environment from any current directory. Linux
desktops need Qt's usual X11/Wayland libraries (for example `libegl1` and
`libxkbcommon0` on Debian/Ubuntu); most desktop installs already have them.

## Other computers running Connectinator

Every running copy announces itself on the local network and lists the others,
so all machines running the app can see each other without scanning. Peers appear
in the device table within a second of starting, marked **Connectinator peer** in
the Discovery column, named by their computer name (a label you set still wins),
and shown **Online** while they keep announcing. Choose **Connectinator peers** in
the status filter to list only them. Their details show the computer name and OS.

- Announcements are small UDP broadcasts on port **47823**, sent every five seconds
  to each local subnet. A new copy says hello and existing copies answer it directly.
  A copy that closes says goodbye; one that goes silent for ~17 seconds is dropped
  from the peer list but stays in the saved inventory like any other device.
- Allow the app through the firewall when Windows or macOS asks on first launch.
  On Linux, open UDP 47823 if a firewall (for example `ufw allow 47823/udp`) is active.
- Broadcasts don't cross routers or most VPNs (including Tailscale), so peers are
  found on the same subnet only. Scan or add other subnets as usual.
- Only the computer name, OS name, and a random per-launch ID are sent. Nothing about
  devices, labels, favorites, or VNC credentials is shared. Turn it off with
  **Settings → Find other computers running Connectinator**.

## Standalone executables

The single-file build is **dist/Connectinator.exe**. Copy just that file to a
Windows x64 machine and double-click it; Python, a virtual environment, and the
source project are not needed. Qt, the theme, and QtAwesome fonts are included.
VNC connections still open an installed VNC viewer selected in Viewer settings.

To rebuild on Windows, run **build.bat**, or use:

```powershell
.venv\Scripts\python.exe -m pip install -e ".[build]"
.venv\Scripts\python.exe scripts\build_exe.py
```

The same script builds natively on Linux (`dist/Connectinator`, a single file) and
macOS (`dist/Connectinator.app`); PyInstaller can't cross-compile, so build on each OS:

```sh
.venv/bin/python -m pip install -e ".[build]"
.venv/bin/python scripts/build_exe.py
```

If an existing EXE is running, build alongside it without replacing it:
`.venv\Scripts\python.exe scripts\build_exe.py --dist-dir dist/updated`.

Build dependencies live in the optional `build` extra in `pyproject.toml`.
The build runs a packaged self-test that renders the UI, checks icons, detects
a fake loopback VNC server, exchanges peer announcements on loopback, and (on
Windows) invokes the packaged ARP helper on loopback.
It writes `build/exe-self-test.json` and a UI image; no LAN scan is performed.
To run it again: `dist\Connectinator.exe --self-test build\exe-self-test.json`.

The executable extracts its bundled runtime to the system temporary directory
while running. Scan defaults, labels, and favorites remain in per-user Qt
settings rather than beside the executable.

## Use

1. Pick a detected network, click **All detected networks**, or enter targets:
   `192.168.1.0/24`, `192.168.1.10-192.168.1.50`, or comma-separated IPv4 addresses/subnets.
   Large interfaces suggest a local `/24` slice; edit Targets to cover other subnets.
2. Choose **Common services + VNC**, **VNC only** (5900–5909), or **Custom ports**.
   Use custom ports for VNC on another port, or additional display ports such as `5910-5999`.
3. Set separate **Connect** and **Greeting** timeouts, then click **Scan network**.
   VNC ports are checked first for each host. Results appear as services are found,
   without waiting for the host's remaining probes or ping. **Stop** preserves partial results.
4. Select a device to inspect services. Verified VNC servers have a valid RFB greeting;
   unverified VNC entries are guesses from the port number. Select an endpoint when a
   machine has multiple VNC servers, then click **Connect to VNC** or double-click its row.
5. Use **Viewer settings** to select an installed VNC viewer if it wasn't detected.
   TigerVNC is a suitable option on every platform. On macOS you can pick the viewer's
   `.app` (TigerVNC Viewer and RealVNC VNC Viewer in Applications are detected). The default `host::port` syntax passes the exact TCP
   port; single-colon syntax is available for viewers that require it. Authentication
   happens in the viewer. Connectinator does not install a viewer or embed a VNC client.

Save a selected device as a favorite for later connections. Favorites retain addresses
and VNC ports, and appear after restart as unverified until scanned again. Filter by
address, service, port, VNC, or favorites. **Export JSON** exports all listed devices
(including rows hidden by filters), service evidence, and whether they responded in
the latest scan. Viewer preferences, favorites, labels, and scan defaults use per-user Qt settings.

## Names, labels, and local discovery

- **Resolve hostnames** performs asynchronous reverse DNS for discovered devices.
  There are at most eight outstanding lookups, with a two-second UI deadline each.
  Successful results are cached for five minutes in this session; failures for 30 seconds.
  Names may be missing if reverse DNS isn't configured. IP addresses remain usable.
- Select a device and click **Edit label…**, or double-click its name column, to assign
  a persistent name such as “Shop workstation.” An empty label restores the resolved
  hostname. Details show both the label and hostname; both are searchable.
- On Windows, **ARP discovery (local subnet)** actively resolves IPv4/MAC addresses
  on directly connected interfaces. This can find devices that block ping and all
  scanned TCP ports. Routed targets, local interface addresses, loopback, and subnet
  broadcast/network addresses are excluded. ARP does not gate TCP scanning.
- ARP uses the Windows SendARP API through a separate helper with eight native calls
  at a time. Stop/window close terminates that helper, including blocked native calls.
  ARP errors are reported while TCP/ping continue. Active ARP is disabled on macOS/Linux.
- The device list uses Qt's table model and filter proxy. Repeated snapshots are
  coalesced by IP and applied every 100 ms, with cached display/search data. Selection
  and the chosen VNC endpoint are preserved as rows arrive or reorder.

## Saved inventory and availability

Discovered devices are saved automatically to a transactional SQLite database in
the per-user Qt application data directory (`devices.sqlite3`). Saves are batched
and flushed on close. The EXE and source app share the same inventory. New scans
update this inventory without discarding previously discovered or offline devices.
Addresses, known services, names, labels, MAC addresses, and timestamps survive restarts.

At startup, saved devices initially appear **Unchecked** and are checked in the
background. **Check saved devices at startup and periodically** is enabled by
default. The default interval is **60 seconds after the previous check completes**;
adjust it from 15 seconds to one hour, disable it, or use **Check now** manually.
Full scans take priority and cancel an active availability check before starting.
Checks never overlap, and stopping/closing retains results already collected.

The table shows **Online**, **Offline**, and **Last seen**, with a status filter.
Offline means no response to the configured checks, which can also indicate a
firewall or network isolation. The previous last-seen timestamp and known VNC ports
are preserved; you can still attempt a connection. Previously saved VNC services
are shown as **Known** until a fresh full scan verifies the greeting again.

Availability checks try up to three known TCP ports, including a VNC endpoint,
then fall back to ping and local Windows ARP when those discovery options are
enabled. They do not repeat the full port scan. Device reachability does not
guarantee that a particular VNC service is accepting connections or credentials.

## Discovery limits

- Scan networks you administer or have permission to inspect. Full scans start on
  request; availability checks of saved addresses run automatically when enabled.
- Devices are discovered through open scanned TCP ports, a successful system ping,
  or a successful local Windows ARP resolution. Devices that block these probes,
  or sit behind isolated network segments, can still be missed.
- VNC detection reads the greeting without authenticating. A verified greeting confirms
  the protocol, not that credentials or a desktop session will be available.
- Other services are labeled by port unless a recognizable SSH greeting is received.
  The app does not enumerate installed processes, UDP services, or operating systems.
- IPv4 only; at most 4,096 hosts and 128 selected TCP ports per scan. TCP concurrency is
  capped at 128, with 16 hosts in progress. No administrator privileges or Nmap needed.
- Increase the relevant timeout for slower links. Common-service scans cap passive
  greetings for known client-first protocols (such as HTTP) at 100 ms; custom scans
  use the full configured greeting timeout on every selected port. A slow VNC server
  on an HTTP-assigned port may therefore need a custom scan. Queued probes and ARP
  timeouts can make large scans take several minutes.
- Ping requires the operating system's `ping` utility; TCP discovery works without it.

## Development

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

On Linux/macOS: `.venv/bin/python -m unittest discover -s tests -v`.

Tests use loopback fake servers, mocked native ARP and DNS, mocked viewer launches,
and an offscreen Qt interface; they do not scan the LAN. Project conventions and a
compact file map are in `AGENTS.md`.

References: [Qt thread signals](https://doc.qt.io/qtforpython-6/PySide6/QtCore/QThread.html)
and [TigerVNC viewer arguments](https://tigervnc.org/doc/vncviewer.html),
[Windows SendARP](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp),
[Qt reverse DNS](https://doc.qt.io/qtforpython-6/PySide6/QtNetwork/QHostInfo.html),
and [Qt table models](https://doc.qt.io/qtforpython-6/PySide6/QtCore/QAbstractTableModel.html).
