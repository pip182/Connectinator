# Connectinator

A PySide6 desktop app for discovering IPv4 devices, inspecting common TCP services,
and quickly connecting to VNC servers with an installed viewer. Icons use QtAwesome.

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

Activation is unnecessary when using the full interpreter path above. On Linux/macOS,
use `.venv/bin/python` instead of `.venv\Scripts\python.exe`.

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
   TigerVNC is a suitable option. The default `host::port` syntax passes the exact TCP
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

## Discovery limits

- Scan networks you administer or have permission to inspect. Scans start only on request.
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

Tests use loopback fake servers, mocked native ARP and DNS, mocked viewer launches,
and an offscreen Qt interface; they do not scan the LAN. Project conventions and a
compact file map are in `AGENTS.md`.

References: [Qt thread signals](https://doc.qt.io/qtforpython-6/PySide6/QtCore/QThread.html)
and [TigerVNC viewer arguments](https://tigervnc.org/doc/vncviewer.html),
[Windows SendARP](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp),
[Qt reverse DNS](https://doc.qt.io/qtforpython-6/PySide6/QtNetwork/QHostInfo.html),
and [Qt table models](https://doc.qt.io/qtforpython-6/PySide6/QtCore/QAbstractTableModel.html).
